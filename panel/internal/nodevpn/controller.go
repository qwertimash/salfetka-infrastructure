// Package nodevpn owns a private engine installation and durable policy watermark.
// A fresh engine epoch must be acknowledged in a NEW signed policy after restart;
// a saved policy is never sufficient to resurrect credentials on a new process.
package nodevpn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"salfetka/panel/internal/leaseclock"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

type Engine interface {
	Apply(nodewire.VPNGrant) error
	Usage(string) (nodewire.VPNUsage, error)
	Epoch() string
	Close() error
}
type Config struct {
	ProfileSHA256                                  string
	Backend                                        string
	StateDir, NodeID, InstallationID, ConfigSHA256 string
	Signer                                         ed25519.PublicKey
	Initialize                                     bool
	Factory                                        func() (Engine, error)
}
type localState struct {
	SchemaVersion  int                       `json:"schema_version"`
	NodeID         string                    `json:"node_id"`
	InstallationID string                    `json:"installation_id"`
	ConfigSHA256   string                    `json:"config_sha256"`
	SignerSHA256   string                    `json:"signer_sha256"`
	Generation     int64                     `json:"generation"`
	Policy         *nodewire.SignedVPNPolicy `json:"policy,omitempty"`
	PolicySHA256   string                    `json:"policy_sha256,omitempty"`
	KnownIDs       []string                  `json:"known_ids"`
	WallHighWater  time.Time                 `json:"wall_high_water"`
	Receipt        *nodewire.VPNReceipt      `json:"receipt,omitempty"`
}
type Controller struct {
	mu               sync.Mutex
	cfg              Config
	state            localState
	dir, lock        int
	engine           Engine
	now              func() time.Time
	monotonic        func() time.Time
	leaseClock       leaseclock.Clock
	persist          func(int, localState) error
	poisoned, closed bool
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var epochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Open(cfg Config) (*Controller, error) {
	if !nodewire.ValidBackend(cfg.Backend) || !idPattern.MatchString(cfg.NodeID) || !idPattern.MatchString(cfg.InstallationID) || !hashPattern.MatchString(cfg.ConfigSHA256) || len(cfg.Signer) != 32 || cfg.Factory == nil {
		return nil, fault("vpn_binding_invalid")
	}
	cfg.Signer = append(ed25519.PublicKey(nil), cfg.Signer...)
	dir, lock, err := openStateDir(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	c := &Controller{cfg: cfg, dir: dir, lock: lock, now: time.Now, monotonic: time.Now, persist: writeState}
	fail := func(e error) (*Controller, error) { c.Close(); return nil, e }

	duplicate, err := unix.Dup(dir)
	if err != nil {
		return fail(fault("vpn_state_directory_invalid"))
	}
	directory := os.NewFile(uintptr(duplicate), "vpn_owned_directory")
	entries, err := directory.ReadDir(-1)
	directory.Close()
	if err != nil {
		return fail(fault("vpn_state_directory_invalid"))
	}
	for _, entry := range entries {
		if entry.Name() != "engine.lock" && entry.Name() != "state.json" && !regexp.MustCompile(`^\.state-[0-9a-f]{32}\.tmp$`).MatchString(entry.Name()) {
			return fail(fault("vpn_foreign_directory"))
		}
	}
	raw, err := readState(dir)
	if err != nil {
		return fail(err)
	}
	if raw == nil {
		if !cfg.Initialize {
			return fail(fault("vpn_initialization_required"))
		}
		c.state = localState{SchemaVersion: 1, NodeID: cfg.NodeID, InstallationID: cfg.InstallationID, ConfigSHA256: cfg.ConfigSHA256, SignerSHA256: hash(cfg.Signer), KnownIDs: []string{}, WallHighWater: c.now().UTC()}
		if err = c.persist(c.dir, c.state); err != nil {
			return fail(fault("vpn_storage_failed"))
		}
	} else {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&c.state) != nil || d.Decode(new(any)) != io.EOF {
			return fail(fault("vpn_state_invalid"))
		}
		canonical, _ := json.Marshal(c.state)
		if !bytes.Equal(append(canonical, '\n'), raw) {
			return fail(fault("vpn_state_invalid"))
		}
		s := c.state
		if s.SchemaVersion != 1 || s.NodeID != cfg.NodeID || s.InstallationID != cfg.InstallationID || s.ConfigSHA256 != cfg.ConfigSHA256 || s.SignerSHA256 != hash(cfg.Signer) || s.WallHighWater.IsZero() || s.Generation < 0 || len(s.KnownIDs) > 256 {
			return fail(fault("vpn_binding_changed"))
		}
		if _, trusted := leaseclock.AwaitRestart(s.WallHighWater); !trusted {
			return fail(fault("vpn_clock_untrusted"))
		}
		if s.Generation == 0 {
			if s.Policy != nil || s.PolicySHA256 != "" || len(s.KnownIDs) != 0 || s.Receipt != nil {
				return fail(fault("vpn_state_invalid"))
			}
		} else {
			if s.Policy == nil {
				return fail(fault("vpn_state_invalid"))
			}
			p, e := nodecontrol.VerifyVPN(cfg.Signer, *s.Policy)
			if e != nil || p.Backend != cfg.Backend || p.ProfileSHA256 != cfg.ProfileSHA256 || p.NodeID != cfg.NodeID || p.InstallationID != cfg.InstallationID || p.Generation != s.Generation || nodecontrol.VPNHash(*s.Policy) != s.PolicySHA256 {
				return fail(fault("vpn_state_invalid"))
			}
		}

		if s.Receipt != nil {
			receipt := s.Receipt
			policy, _ := nodecontrol.VerifyVPN(cfg.Signer, *s.Policy)
			if receipt.SchemaVersion != 1 || receipt.NodeID != s.NodeID || receipt.InstallationID != s.InstallationID || receipt.Generation != s.Generation || receipt.PolicySHA256 != s.PolicySHA256 || receipt.Status != "applied" || receipt.ErrorCode != "" || receipt.CompletedAt.Before(policy.IssuedAt.Add(-time.Second)) || receipt.CompletedAt.After(s.WallHighWater) || len(receipt.Usage) != len(policy.Grants) {
				return fail(fault("vpn_state_invalid"))
			}
			for i, u := range receipt.Usage {
				g := policy.Grants[i]
				if u.GrantID != g.ID || u.Generation != s.Generation || u.InstanceEpoch != policy.EngineEpoch || u.Active != (g.Enabled && receipt.CompletedAt.Before(g.ExpiresAt)) || (u.Uplink != nil && *u.Uplink < 0) || (u.Downlink != nil && *u.Downlink < 0) {
					return fail(fault("vpn_state_invalid"))
				}
			}
		}
		prior := ""
		for _, id := range s.KnownIDs {
			if !idPattern.MatchString(id) || id <= prior {
				return fail(fault("vpn_state_invalid"))
			}
			prior = id
		}
	}
	sample := time.Now()
	c.leaseClock = leaseclock.New(sample, sample)
	engine, err := cfg.Factory()
	if err != nil {
		return fail(fault("vpn_engine_start_failed"))
	}
	c.engine = engine
	if c.engine == nil {
		return fail(fault("vpn_engine_start_failed"))
	}
	if !epochPattern.MatchString(c.engine.Epoch()) {
		return fail(fault("vpn_engine_epoch_invalid"))
	}
	return c, nil
}
func (c *Controller) trustedNow() (time.Time, error) {
	now, trusted := c.leaseClock.Observe(c.now(), c.monotonic())
	if !trusted || now.Before(c.state.WallHighWater) {
		c.poisoned = true
		c.engine.Close()
		return time.Time{}, fault("vpn_clock_untrusted")
	}
	return now, nil
}
func (c *Controller) save(next localState) error {
	now, err := c.trustedNow()
	if err != nil {
		return err
	}
	if now.After(next.WallHighWater) {
		next.WallHighWater = now
	}
	if c.persist(c.dir, next) != nil {
		c.poisoned = true
		c.engine.Close()
		return fault("vpn_storage_failed")
	}
	c.state = next
	return nil
}
func (c *Controller) Epoch() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine == nil {
		return ""
	}
	return c.engine.Epoch()
}
func (c *Controller) Apply(s nodewire.SignedVPNPolicy) (nodewire.VPNReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var empty nodewire.VPNReceipt
	if c.closed || c.poisoned {
		return empty, fault("vpn_runtime_unavailable")
	}
	p, err := nodecontrol.VerifyVPN(c.cfg.Signer, s)
	if err != nil {
		return empty, fault("vpn_signature_invalid")
	}
	if p.Backend != c.cfg.Backend || p.ProfileSHA256 != c.cfg.ProfileSHA256 || p.NodeID != c.cfg.NodeID || p.InstallationID != c.cfg.InstallationID || p.EngineEpoch != c.engine.Epoch() {
		return empty, fault("vpn_target_mismatch")
	}
	now, err := c.trustedNow()
	if err != nil {
		return empty, err
	}
	if now.Before(p.IssuedAt.Add(-time.Second)) || !now.Before(p.ExpiresAt) {
		return empty, fault("vpn_lease_expired")
	}
	digest := nodecontrol.VPNHash(s)
	if p.Generation < c.state.Generation || (p.Generation == c.state.Generation && digest != c.state.PolicySHA256) {
		return empty, fault("vpn_generation_conflict")
	}
	if p.Generation == c.state.Generation && c.state.Receipt != nil {
		return cloneReceipt(*c.state.Receipt), nil
	}
	ids := map[string]bool{}
	for _, id := range c.state.KnownIDs {
		ids[id] = true
	}
	for _, g := range p.Grants {
		ids[g.ID] = true
	}
	known := make([]string, 0, len(ids))
	for id := range ids {
		known = append(known, id)
	}
	sort.Strings(known)
	next := c.state
	next.Generation = p.Generation
	next.Policy = &s
	next.PolicySHA256 = digest
	next.KnownIDs = known
	next.Receipt = nil
	if err = c.save(next); err != nil {
		return empty, err
	}
	desired := map[string]nodewire.VPNGrant{}
	for _, g := range p.Grants {
		desired[g.ID] = g
	}
	// Deny absent/disabled/expired credentials BEFORE enabling any new ones.
	for _, id := range known {
		g, ok := desired[id]
		if !ok || !g.Enabled || !now.Before(g.ExpiresAt) {
			if err = c.engine.Apply(nodewire.VPNGrant{ID: id, Generation: p.Generation}); err != nil {
				return empty, c.applyFailed(engineFailure(err))
			}
		}
	}
	for _, g := range p.Grants {
		if g.Enabled && now.Before(g.ExpiresAt) {
			if err = c.engine.Apply(g); err != nil {
				return empty, c.applyFailed(engineFailure(err))
			}
		}
	}
	completed, err := c.trustedNow()
	if err != nil {
		return empty, err
	}
	receipt := nodewire.VPNReceipt{SchemaVersion: 1, NodeID: p.NodeID, InstallationID: p.InstallationID, Generation: p.Generation, PolicySHA256: digest, Status: "applied", Usage: []nodewire.VPNUsage{}, CompletedAt: completed}
	current := make([]string, 0, len(p.Grants))
	for _, g := range p.Grants {
		u, e := c.engine.Usage(g.ID)
		if e != nil || u.Generation != p.Generation || u.InstanceEpoch != p.EngineEpoch {
			return empty, c.applyFailed("vpn_engine_readback_failed")
		}
		if u.Active != (g.Enabled && receipt.CompletedAt.Before(g.ExpiresAt)) {
			return empty, c.applyFailed("vpn_engine_activity_mismatch")
		}
		receipt.Usage = append(receipt.Usage, u)
		current = append(current, g.ID)
	}
	next = c.state
	stored := cloneReceipt(receipt)
	next.Receipt = &stored
	next.KnownIDs = current
	if err = c.save(next); err != nil {
		return empty, err
	}
	return receipt, nil
}
func engineFailure(err error) string {
	if err.Error() == "engine_clock_untrusted" {
		return "vpn_engine_clock_untrusted"
	}
	return "vpn_engine_grant_failed"
}
func (c *Controller) applyFailed(code string) error {
	c.poisoned = true
	c.engine.Close()
	return fault(code)
}
func (c *Controller) Usage() ([]nodewire.VPNUsage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned {
		return nil, fault("vpn_runtime_unavailable")
	}
	out := []nodewire.VPNUsage{}
	for _, id := range c.state.KnownIDs {
		v, e := c.engine.Usage(id)
		if e != nil {
			return nil, fault("vpn_readback_failed")
		}
		out = append(out, v)
	}
	return out, nil
}

// ObservedAt uses the same conservative clock as policy receipts and leases.
// Raw wall time can briefly precede a receipt after a synchronization correction.
func (c *Controller) ObservedAt() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.poisoned {
		return time.Time{}, fault("vpn_runtime_unavailable")
	}
	return c.trustedNow()
}
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.engine != nil {
		c.engine.Close()
	}
	unix.Close(c.lock)
	unix.Close(c.dir)
}

func cloneReceipt(r nodewire.VPNReceipt) nodewire.VPNReceipt {
	b, _ := json.Marshal(r)
	var out nodewire.VPNReceipt
	json.Unmarshal(b, &out)
	return out
}

func (c *Controller) Backend() string { return c.cfg.Backend }

func (c *Controller) ProfileSHA256() string { return c.cfg.ProfileSHA256 }
