// Loopback fixtures derived from B0. The separate server patch must terminate
// active sessions; historical B0 sources and negative receipts stay unchanged.
package xrayengine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	handlerapi "github.com/xtls/xray-core/app/proxyman/command"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	statsapi "github.com/xtls/xray-core/app/stats/command"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	hyaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/vless"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

const deadline = 3 * time.Second
const revokeObservationWindow = 31 * time.Second // Exceeds the plan's 30 s online-revoke target.

type identity struct{ Email, Secret string }

var users = []identity{
	{"a@b0.invalid", "11111111-1111-4111-8111-111111111111"},
	{"b@b0.invalid", "22222222-2222-4222-8222-222222222222"},
}

type observation struct {
	Backend                   string           `json:"backend"`
	HarnessPassed             bool             `json:"harness_passed"`
	UsersAfterAdd             []string         `json:"users_after_add"`
	UsersAfterRemove          []string         `json:"users_after_remove"`
	OldTCPAfterRemove         bool             `json:"a_old_tcp_after_remove"`
	OldUDPAfterRemove         bool             `json:"a_old_udp_after_remove"`
	NewTCPExistingCarrier     bool             `json:"a_new_tcp_existing_client_after_remove"`
	NewUDPExistingCarrier     bool             `json:"a_new_udp_existing_client_after_remove"`
	FreshClientTCPAfterRemove bool             `json:"a_fresh_client_tcp_after_remove"`
	FreshClientUDPAfterRemove bool             `json:"a_fresh_client_udp_after_remove"`
	FreshClientTCPOutcome     string           `json:"a_fresh_client_tcp_outcome"`
	FreshClientUDPOutcome     string           `json:"a_fresh_client_udp_outcome"`
	RevokeObservationMillis   int64            `json:"revoke_observation_millis"`
	BExistingAndNewContinue   bool             `json:"b_existing_and_new_continue"`
	ReaddRestoresNewAccess    bool             `json:"readd_restores_new_access"`
	CountersAfterTCP          map[string]int64 `json:"counters_after_tcp"`
	CountersAfterUDP          map[string]int64 `json:"counters_after_udp"`
	CountersBeforeReset       map[string]int64 `json:"counters_before_reset"`
	CountersResetReturned     map[string]int64 `json:"counters_reset_returned"`
	CountersAfterReset        map[string]int64 `json:"counters_after_reset"`
	CountersAfterResetTraffic map[string]int64 `json:"counters_after_reset_traffic"`
	RestartCountersEmpty      bool             `json:"restart_counters_empty"`
}

type certs struct{ root, leaf, key []string }

func syntheticCert(t *testing.T) certs {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "B0 temporary CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"b0.invalid"},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	lines := func(kind string, b []byte) []string {
		return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b}))), "\n")
	}
	return certs{lines("CERTIFICATE", der), lines("CERTIFICATE", leafDER), lines("PRIVATE KEY", keyDER)}
}

func stream(kind string, ca certs, server bool, secret string) map[string]any {
	network, alpn := "tcp", "http/1.1"
	if kind == "hy2_xray" {
		network, alpn = "hysteria", "h3"
	}
	tls := map[string]any{"serverName": "b0.invalid", "alpn": []string{alpn}}
	if server {
		tls["certificates"] = []any{map[string]any{"certificate": ca.leaf, "key": ca.key}}
	} else {
		tls["disableSystemRoot"] = true
		tls["certificates"] = []any{map[string]any{"certificate": ca.root, "usage": "verify"}}
	}
	s := map[string]any{"network": network, "security": "tls", "tlsSettings": tls}
	if kind == "hy2_xray" {
		h := map[string]any{"version": 2}
		// A shared fallback auth on the server would invalidate per-user revoke.
		if !server {
			h["auth"] = secret
		}
		s["hysteriaSettings"] = h
		s["finalmask"] = map[string]any{"quicParams": map[string]any{"congestion": "bbr"}}
	}
	return s
}

func freePort(t *testing.T, udp bool) int {
	t.Helper()
	if udp {
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type engine struct {
	*xcore.Instance
	once     sync.Once
	closeErr error
}

func (e *engine) Close() error {
	e.once.Do(func() { e.closeErr = e.Instance.Close() })
	return e.closeErr
}

func startEngine(t *testing.T, m map[string]any) *engine {
	t.Helper()
	m["log"] = map[string]any{"loglevel": "none", "access": "none", "error": "none"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c conf.Config
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	built, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	x, err := xcore.New(built)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{Instance: x}
	t.Cleanup(func() {
		done := make(chan error, 1)
		go func() { done <- e.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error("engine cleanup:", err)
			}
		case <-time.After(deadline):
			t.Error("engine cleanup timeout")
		}
	})
	if err = x.Start(); err != nil {
		t.Fatal(err)
	}
	return e
}

type server struct {
	engine *engine
	port   int
	api    handlerapi.HandlerServiceClient
	stats  statsapi.StatsServiceClient
}

func startServer(t *testing.T, kind string, ca certs) *server {
	t.Helper()
	port, apiPort := freePort(t, kind == "hy2_xray"), freePort(t, false)
	protoName := "vless"
	settings := map[string]any{"decryption": "none", "clients": []any{}}
	if kind == "hy2_xray" {
		protoName, settings = "hysteria", map[string]any{"version": 2, "users": []any{}}
	}
	x := startEngine(t, map[string]any{
		"api":       map[string]any{"tag": "api", "listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)), "services": []string{"HandlerService", "StatsService"}},
		"stats":     map[string]any{},
		"policy":    map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}},
		"inbounds":  []any{map[string]any{"tag": "vpn", "listen": "127.0.0.1", "port": port, "protocol": protoName, "settings": settings, "streamSettings": stream(kind, ca, true, "")}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1"}}, map[string]any{"action": "block"}}}}},
	})
	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	s := &server{x, port, handlerapi.NewHandlerServiceClient(conn), statsapi.NewStatsServiceClient(conn)}
	// The request waits for actual gRPC readiness; no guessed startup sleep.
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	_, err = s.api.GetInboundUsers(ctx, &handlerapi.GetInboundUserRequest{Tag: "vpn"}, grpc.WaitForReady(true))
	if err != nil {
		t.Fatal("API readiness:", err)
	}
	return s
}

func (s *server) change(t *testing.T, kind string, u identity, add bool) {
	t.Helper()
	var op proto.Message = &handlerapi.RemoveUserOperation{Email: u.Email}
	if add {
		var account proto.Message = &vless.Account{Id: u.Secret, Encryption: "none"}
		if kind == "hy2_xray" {
			account = &hyaccount.Account{Auth: u.Secret}
		}
		op = &handlerapi.AddUserOperation{User: &protocol.User{Email: u.Email, Account: serial.ToTypedMessage(account)}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	if _, err := s.api.AlterInbound(ctx, &handlerapi.AlterInboundRequest{Tag: "vpn", Operation: serial.ToTypedMessage(op)}); err != nil {
		t.Fatal("user mutation:", err)
	}
}

func (s *server) userList(t *testing.T) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	r, err := s.api.GetInboundUsers(ctx, &handlerapi.GetInboundUserRequest{Tag: "vpn"})
	if err != nil {
		t.Fatal(err)
	}
	list := []string{}
	for _, u := range r.Users {
		list = append(list, u.Email)
	}
	sort.Strings(list)
	return list
}

func (s *server) counters(t *testing.T, reset bool) map[string]int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	r, err := s.stats.QueryStats(ctx, &statsapi.QueryStatsRequest{Pattern: "user>>>", Reset_: reset})
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]int64{}
	for _, v := range r.Stat {
		values[v.Name] = v.Value
	}
	return values
}

func startClient(t *testing.T, kind string, port int, ca certs, u identity) *engine {
	t.Helper()
	name := "vless"
	settings := map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": u.Secret, "encryption": "none"}}}}}
	if kind == "hy2_xray" {
		name, settings = "hysteria", map[string]any{"version": 2, "address": "127.0.0.1", "port": port}
	}
	return startEngine(t, map[string]any{"outbounds": []any{map[string]any{"protocol": name, "settings": settings, "streamSettings": stream(kind, ca, false, u.Secret)}}})
}

// Loopback services accept only synthetic probes, with finite connection lifetimes.
func echoes(t *testing.T) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	connections := []net.Conn{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(45 * time.Second))
				io.Copy(c, c)
			}()
		}
	}()
	go func() {
		defer wg.Done()
		b := make([]byte, 65536)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err = udp.WriteTo(b[:n], a); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		tcp.Close()
		udp.Close()
		mu.Lock()
		for _, c := range connections {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return tcp.Addr().String(), udp.LocalAddr().String()
}

type flow struct {
	c       net.Conn
	cancel  context.CancelFunc
	outcome string
}

func openFlow(t *testing.T, x *engine, network, addr string) *flow {
	t.Helper()
	dest, err := xnet.ParseDestination(network + ":" + addr)
	if err != nil {
		t.Fatal(err)
	}
	if !dest.Address.IP().IsLoopback() {
		t.Fatal("non-loopback probe refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := xcore.Dial(ctx, x.Instance, dest)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &flow{c: c, cancel: cancel}
	t.Cleanup(f.close)
	return f
}

func (f *flow) close() { f.cancel(); f.c.Close() }

func (f *flow) exchange(payload []byte) bool {
	// core.Dial's virtual connection has no deadlines. Cancel AND close on timeout
	// and join the operation so negative probes cannot leave a blocked reader.
	done := make(chan string, 1)
	go func() {
		if _, err := f.c.Write(payload); err != nil {
			done <- "write_error"
			return
		}
		b := make([]byte, len(payload))
		_, err := io.ReadFull(f.c, b)
		switch {
		case err != nil:
			done <- "read_error"
		case !bytes.Equal(b, payload):
			done <- "payload_mismatch"
		default:
			done <- "success"
		}
	}()
	select {
	case outcome := <-done:
		f.outcome = outcome
		return outcome == "success"
	case <-time.After(deadline):
		f.outcome = "timeout"
		f.close()
		select {
		case <-done:
		case <-time.After(deadline):
			panic("probe failed to stop after cancellation")
		}
		return false
	}
}

func one(t *testing.T, x *engine, network, addr string) bool {
	t.Helper()
	f := openFlow(t, x, network, addr)
	defer f.close()
	return f.exchange([]byte("fresh-" + network + "-b0"))
}

func check(t *testing.T, condition bool, message string) {
	t.Helper()
	if !condition {
		t.Fatal(message)
	}
}

func trafficKey(email, direction string) string {
	return "user>>>" + email + ">>>traffic>>>" + direction
}
