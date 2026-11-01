package nodevpn

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"salfetka/panel/internal/leaseclock"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"sync"
	"time"
)

type FleetController interface {
	Epoch() string
	Apply(nodewire.SignedVPNPolicy) (nodewire.VPNReceipt, error)
	Usage() ([]nodewire.VPNUsage, error)
	ObservedAt() (time.Time, error)
	Close()
}
type FleetConfig struct {
	StateDir, NodeID string
	Signer           ed25519.PublicKey
	Initialize       bool
	Open             func(nodewire.ConnectionDeployment, string, bool) (FleetController, error)
}
type FleetStatus = nodewire.ConnectionState
type fleetVersion struct {
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
}
type fleetState struct {
	Version       int                     `json:"version"`
	NodeID        string                  `json:"node_id"`
	SignerHash    string                  `json:"signer_hash"`
	Revision      int64                   `json:"revision"`
	DesiredHash   string                  `json:"desired_hash"`
	Seen          map[string]fleetVersion `json:"seen"`
	WallHighWater time.Time               `json:"wall_high_water"`
}
type fleetEntry struct {
	Deployment nodewire.ConnectionDeployment
	Controller FleetController
}
type Fleet struct {
	mu               sync.Mutex
	cfg              FleetConfig
	state            fleetState
	dir, lock        int
	entries          map[string]fleetEntry
	statuses         []FleetStatus
	deadline         time.Time
	clock            leaseclock.Clock
	closed, poisoned bool
	stop, done       chan struct{}
	persist          func(int, any) error
}

func OpenFleet(cfg FleetConfig) (*Fleet, error) {
	if !idPattern.MatchString(cfg.NodeID) || len(cfg.Signer) != 32 || cfg.Open == nil {
		return nil, fault("fleet_binding_invalid")
	}
	fd, lock, e := openStateDir(cfg.StateDir)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Fleet, error) { unix.Close(lock); unix.Close(fd); return nil, e }
	raw, e := readState(fd)
	if e != nil {
		return fail(e)
	}
	now := time.Now()
	s := fleetState{Version: 1, NodeID: cfg.NodeID, SignerHash: hash(cfg.Signer), Seen: map[string]fleetVersion{}, WallHighWater: now.UTC()}
	if raw == nil {
		if !cfg.Initialize {
			return fail(fault("fleet_not_initialized"))
		}
		if e = writeStateValue(fd, s); e != nil {
			return fail(e)
		}
	} else {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&s) != nil || s.Version != 1 || s.NodeID != cfg.NodeID || s.SignerHash != hash(cfg.Signer) || s.Revision < 0 || s.Seen == nil || s.WallHighWater.IsZero() {
			return fail(fault("fleet_state_invalid"))
		}
		if now.Before(s.WallHighWater) {
			return fail(fault("fleet_clock_untrusted"))
		}
	}
	f := &Fleet{cfg: cfg, state: s, dir: fd, lock: lock, entries: map[string]fleetEntry{}, clock: leaseclock.New(now, now), stop: make(chan struct{}), done: make(chan struct{}), persist: writeStateValue}
	go f.watch()
	return f, nil
}
func (f *Fleet) stopEngines() {
	for id, e := range f.entries {
		e.Controller.Close()
		delete(f.entries, id)
	}
}
func (f *Fleet) watch() {
	defer close(f.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-f.stop:
			return
		case <-ticker.C:
			f.mu.Lock()
			sample := time.Now()
			now, ok := f.clock.Observe(sample, sample)
			if !ok {
				f.poisoned = true
			}
			if !ok || (!f.deadline.IsZero() && !now.Before(f.deadline)) {
				f.stopEngines()
			}
			f.mu.Unlock()
		}
	}
}

// Apply commits the revision watermark before touching listeners. It never
// starts saved configurations on boot; a fresh signed plan is required.
func (f *Fleet) Apply(s nodewire.SignedConnectionsPlan) ([]FleetStatus, error) {
	p, e := nodecontrol.VerifyConnections(f.cfg.Signer, s)
	if e != nil {
		return nil, fault("fleet_plan_invalid")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.poisoned {
		return nil, fault("fleet_unavailable")
	}
	sample := time.Now()
	now, ok := f.clock.Observe(sample, sample)
	if !ok {
		f.poisoned = true
		f.stopEngines()
		return nil, fault("fleet_clock_untrusted")
	}
	if p.NodeID != f.cfg.NodeID || p.IssuedAt.After(now.Add(time.Second)) || !now.Before(p.ExpiresAt) {
		return nil, fault("fleet_plan_expired")
	}
	// Time renewal is allowed without a configuration revision change.
	raw, _ := json.Marshal(p.Connections)
	digest := hash(raw)
	clear(raw)
	if p.Revision < f.state.Revision || (p.Revision == f.state.Revision && f.state.DesiredHash != digest) {
		return nil, fault("fleet_plan_replay")
	}
	next := f.state
	next.Seen = map[string]fleetVersion{}
	for id, v := range f.state.Seen {
		next.Seen[id] = v
	}
	for _, c := range p.Connections {
		old, exists := next.Seen[c.ID]
		if exists && (c.Revision < old.Revision || (c.Revision == old.Revision && c.ConfigurationSHA256 != old.Hash)) {
			return nil, fault("fleet_connection_replay")
		}
		next.Seen[c.ID] = fleetVersion{c.Revision, c.ConfigurationSHA256}
	}
	if len(next.Seen) > 256 {
		return nil, fault("fleet_history_capacity")
	}
	next.Revision = p.Revision
	next.DesiredHash = digest
	next.WallHighWater = now
	if e = f.persist(f.dir, next); e != nil {
		f.poisoned = true
		f.stopEngines()
		return nil, fault("fleet_storage_failed")
	}
	f.state = next
	f.deadline = p.ExpiresAt
	wanted := map[string]nodewire.ConnectionDeployment{}
	for _, c := range p.Connections {
		wanted[c.ID] = c
	}
	for id, old := range f.entries {
		c, exists := wanted[id]
		if !exists || !c.Enabled || c.Revision != old.Deployment.Revision || c.ConfigurationSHA256 != old.Deployment.ConfigurationSHA256 {
			old.Controller.Close()
			delete(f.entries, id)
		}
	}
	f.statuses = []FleetStatus{}
	for _, c := range p.Connections {
		status := FleetStatus{ID: c.ID, Revision: c.Revision, State: "disabled"}
		if c.Enabled {
			if _, exists := f.entries[c.ID]; !exists {
				dir := filepath.Join(f.cfg.StateDir, fmt.Sprintf("connection-%s-%d", c.ID, c.Revision))
				_, err := os.Lstat(filepath.Join(dir, "state.json"))
				initialize := os.IsNotExist(err)
				controller, err := f.cfg.Open(c, dir, initialize)
				if err != nil {
					status.State = "failed"
					status.ErrorCode = "connection_start_failed"
					f.statuses = append(f.statuses, status)
					continue
				}
				f.entries[c.ID] = fleetEntry{c, controller}
			}
			status.State = "listening"
		}
		f.statuses = append(f.statuses, status)
	}
	// The wire protocol distinguishes an empty report from a missing report.
	return append([]FleetStatus{}, f.statuses...), nil
}

// WithConnection prevents replacement/expiry while the callback applies a
// bounded policy. Network calls must happen before this method.
func (f *Fleet) WithConnection(id, epoch string, fn func(FleetController) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.poisoned {
		return fault("fleet_unavailable")
	}
	e, ok := f.entries[id]
	if !ok || e.Controller.Epoch() != epoch {
		return fault("fleet_connection_changed")
	}
	return fn(e.Controller)
}

type FleetBinding struct {
	Deployment nodewire.ConnectionDeployment
	Epoch      string
}

func (f *Fleet) Bindings() []FleetBinding {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []FleetBinding{}
	for _, e := range f.entries {
		out = append(out, FleetBinding{e.Deployment, e.Controller.Epoch()})
	}
	return out
}
func (f *Fleet) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	close(f.stop)
	f.stopEngines()
	f.mu.Unlock()
	<-f.done
	unix.Close(f.lock)
	unix.Close(f.dir)
}

func (f *Fleet) Drop(id, epoch string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[id]
	if ok && e.Controller.Epoch() == epoch {
		e.Controller.Close()
		delete(f.entries, id)
	}
}
