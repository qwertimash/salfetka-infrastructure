// Package xrayengine provides a narrow, process-owned VLESS RAW/TLS runtime.
// Its caller must verify signed grants and persist generations BEFORE Apply.
// It exposes no arbitrary Xray JSON, network administration API or PID adoption.
package xrayengine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/leaseclock"
	"salfetka/panel/internal/nodewire"

	"github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/vless"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
)

var (
	ErrInvalid  = errors.New("engine_invalid")
	ErrConflict = errors.New("engine_generation_conflict")
	ErrExpired  = errors.New("engine_lease_expired")
	ErrClosed   = errors.New("engine_closed")
	ErrClock    = errors.New("engine_clock_untrusted")
	ErrApply    = errors.New("engine_apply_failed")
)

const MaxLease = 5 * time.Minute
const tag = "managed-vless"

type Config struct {
	Connection *connection.Configuration `json:",omitempty"`
	// TrafficGate is opt-in; a trusted adapter maps grant IDs to canonical accounts.
	// It is invoked on existing streams as well as new ones. No raw VPN key is passed.
	TrafficGate    func(context.Context, string, string, int) error `json:"-"`
	Backend        string                                           `json:",omitempty"`
	ListenIP       string
	Port           int
	CertificatePEM string
	KeyPEM         string
	// LabLoopbackOnly forbids any egress except loopback in isolated probes.
	LabLoopbackOnly bool
}
type Grant = nodewire.VPNGrant
type Usage = nodewire.VPNUsage
type record struct {
	grant    Grant
	hash     [32]byte
	active   bool
	deadline time.Time
}
type Runtime struct {
	backend        string
	mu             sync.Mutex
	engine         *core.Instance
	users          proxy.UserManager
	stats          stats.Manager
	records        map[string]*record
	epoch          string
	closed         bool
	clockBad       bool
	highWall       time.Time
	now            func() time.Time
	monotonic      func() time.Time
	leaseClock     leaseclock.Clock
	done           chan struct{}
	wg             sync.WaitGroup
	closeOnce      sync.Once
	engineStopOnce sync.Once
	closeErr       error
}

func validID(s string) bool  { u, err := uuid.ParseString(s); return err == nil && u.String() == s }
func email(id string) string { return "grant-" + id }

func New(c Config) (*Runtime, error) {
	if c.Connection != nil {
		if c.Connection.ReadyAt(time.Now()) != nil {
			return nil, ErrInvalid
		}
		c.ListenIP, c.Port = c.Connection.Public.ListenIP, c.Connection.Public.Port
		c.CertificatePEM, c.KeyPEM = c.Connection.Private.CertificatePEM, c.Connection.Private.KeyPEM
		c.Backend = "vless"
		if c.Connection.Public.Template == connection.Hy2 {
			c.Backend = "hysteria2"
		}
	}
	if c.Backend != "" && c.Backend != "vless" && c.Backend != "hysteria2" {
		return nil, ErrInvalid
	}
	if net.ParseIP(c.ListenIP) == nil || c.Port < 1 || c.Port > 65535 || (c.Connection == nil && (c.CertificatePEM == "" || c.KeyPEM == "")) {
		return nil, ErrInvalid
	}
	lines := func(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }
	outbound := map[string]any{"protocol": "freedom", "settings": map[string]any{}}
	if c.LabLoopbackOnly {
		outbound["settings"] = map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1", "::1"}}, map[string]any{"action": "block"}}}
	}
	spec := map[string]any{
		"log":   map[string]any{"loglevel": "none", "access": "none", "error": "none"},
		"stats": map[string]any{}, "policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}},
		"inbounds":  []any{map[string]any{"tag": tag, "listen": c.ListenIP, "port": c.Port, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"alpn": []string{"http/1.1"}, "certificates": []any{map[string]any{"certificate": lines(c.CertificatePEM), "key": lines(c.KeyPEM)}}}}}},
		"outbounds": []any{outbound},
	}
	if c.Backend == "hysteria2" {
		spec["inbounds"] = []any{map[string]any{"tag": tag, "listen": c.ListenIP, "port": c.Port, "protocol": "hysteria", "settings": map[string]any{"version": 2, "users": []any{}}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificate": lines(c.CertificatePEM), "key": lines(c.KeyPEM)}}}}}}
	}
	if c.Connection != nil {
		stream, e := c.Connection.ServerStream()
		if e != nil {
			return nil, ErrInvalid
		}
		spec["inbounds"].([]any)[0].(map[string]any)["streamSettings"] = stream
	}
	raw, _ := json.Marshal(spec)
	var parsed conf.Config
	if json.Unmarshal(raw, &parsed) != nil {
		return nil, ErrInvalid
	}
	built, err := parsed.Build()
	if err != nil {
		return nil, ErrInvalid
	}
	instance, err := core.New(built)
	if err != nil {
		return nil, ErrApply
	}
	fail := func() (*Runtime, error) { instance.Close(); return nil, ErrApply }
	manager, ok := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		return fail()
	}
	handler, err := manager.GetHandler(context.Background(), tag)
	if err != nil {
		return fail()
	}
	getter, ok := handler.(proxy.GetInbound)
	if !ok {
		return fail()
	}
	users, ok := getter.GetInbound().(proxy.UserManager)
	if !ok {
		return fail()
	}
	counters, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return fail()
	}
	if c.TrafficGate != nil {
		d, ok := instance.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
		if !ok {
			return fail()
		}
		d.SetTrafficGate(func(ctx context.Context, user, direction string, size int) error {
			if !strings.HasPrefix(user, "grant-") || !validID(strings.TrimPrefix(user, "grant-")) {
				return ErrInvalid
			}
			return c.TrafficGate(ctx, strings.TrimPrefix(user, "grant-"), direction, size)
		})
	}
	var epoch [16]byte
	if _, err = rand.Read(epoch[:]); err != nil {
		return fail()
	}
	r := &Runtime{backend: c.Backend, engine: instance, users: users, stats: counters, records: make(map[string]*record), epoch: hex.EncodeToString(epoch[:]), now: time.Now, monotonic: time.Now, done: make(chan struct{})}
	r.highWall = r.now().UTC()
	r.leaseClock = leaseclock.New(r.highWall, r.monotonic())
	if err = instance.Start(); err != nil {
		return fail()
	}
	r.wg.Add(1)
	go r.watch()
	return r, nil
}

func (r *Runtime) stopLocked(v *record) error {
	if !v.active {
		return nil
	}
	if err := r.users.RemoveUser(context.Background(), email(v.grant.ID)); err != nil {
		return ErrApply
	}
	if r.users.GetUser(context.Background(), email(v.grant.ID)) != nil {
		return ErrApply
	}
	v.active = false
	return nil
}
func (r *Runtime) checkClockLocked(now time.Time) bool {
	var trusted bool
	r.highWall, trusted = r.leaseClock.Observe(now, r.monotonic())
	r.clockBad = !trusted
	if r.clockBad {
		for _, v := range r.records {
			if r.stopLocked(v) != nil {
				r.stopEngine()
				r.closed = true
			}
		}
	}
	return !r.clockBad
}
func (r *Runtime) watch() {
	defer r.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.mu.Lock()
			if !r.closed {
				now := r.now()
				if r.checkClockLocked(now) {
					for _, v := range r.records {
						if v.active && (!now.Before(v.deadline) || !r.highWall.Before(v.grant.ExpiresAt)) {
							if r.stopLocked(v) != nil {
								r.stopEngine()
								r.closed = true
								break
							}
						}
					}
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *Runtime) Apply(g Grant) error {
	if !validID(g.ID) || g.Generation < 1 {
		return ErrInvalid
	}
	if g.Enabled {
		if !validID(g.Credential) || g.ExpiresAt.IsZero() {
			return ErrInvalid
		}
	} else if g.Credential != "" || !g.ExpiresAt.IsZero() {
		return ErrInvalid
	}
	g.ExpiresAt = g.ExpiresAt.UTC()
	raw, _ := json.Marshal(g)
	hash := sha256.Sum256(raw)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	now := r.now()
	if !r.checkClockLocked(now) {
		return ErrClock
	}
	old := r.records[g.ID]
	if old != nil {
		if g.Generation < old.grant.Generation {
			return ErrConflict
		}
		if g.Generation == old.grant.Generation {
			if hash != old.hash {
				return ErrConflict
			}
			if g.Enabled && (!old.active || !now.Before(old.deadline) || !r.highWall.Before(g.ExpiresAt)) {
				return ErrExpired
			}
			return nil
		}
	}
	if g.Enabled && (!r.highWall.Before(g.ExpiresAt) || g.ExpiresAt.Sub(r.highWall) > MaxLease) {
		return ErrExpired
	}
	keep := old != nil && old.active && g.Enabled && g.Credential == old.grant.Credential
	if old != nil && !keep {
		if err := r.stopLocked(old); err != nil {
			return err
		}
	}
	next := &record{grant: g, hash: hash, active: keep}
	if g.Enabled {
		if !keep {
			typed := serial.ToTypedMessage(&vless.Account{Id: g.Credential, Encryption: "none"})
			if r.backend == "hysteria2" {
				typed = serial.ToTypedMessage(&account.Account{Auth: g.Credential})
			}
			u, err := (&protocol.User{Email: email(g.ID), Account: typed}).ToMemoryUser()
			if err != nil {
				return ErrInvalid
			}
			if r.users.AddUser(context.Background(), u) != nil {
				return ErrApply
			}
			next.active = true
		}
		next.deadline = now.Add(g.ExpiresAt.Sub(r.highWall))
		if r.users.GetUser(context.Background(), email(g.ID)) == nil {
			return ErrApply
		}
	}
	r.records[g.ID] = next
	return nil
}

func (r *Runtime) Usage(id string) (Usage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.records[id]
	if v == nil {
		return Usage{}, ErrInvalid
	}
	out := Usage{GrantID: id, InstanceEpoch: r.epoch, Generation: v.grant.Generation, Active: v.active && !r.closed}
	for _, direction := range []string{"uplink", "downlink"} {
		if c := r.stats.GetCounter("user>>>" + email(id) + ">>>traffic>>>" + direction); c != nil {
			value := c.Value()
			if direction == "uplink" {
				out.Uplink = &value
			} else {
				out.Downlink = &value
			}
		}
	}
	return out, nil
}
func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		for _, v := range r.records {
			_ = r.stopLocked(v)
		}
		close(r.done)
		r.mu.Unlock()
		r.wg.Wait()
		r.closeErr = r.stopEngine()
	})
	return r.closeErr
}

func (r *Runtime) stopEngine() error {
	r.engineStopOnce.Do(func() {
		if closer, ok := r.users.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		r.closeErr = r.engine.Close()
	})
	return r.closeErr
}

func (r *Runtime) Epoch() string { return r.epoch }
