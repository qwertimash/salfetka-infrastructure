package nodevpn

import (
	"errors"
	"os"
	"path/filepath"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

type fakeEngine struct {
	epoch  string
	closed bool
	grants map[string]nodewire.VPNGrant
	calls  int
}

func (e *fakeEngine) Apply(g nodewire.VPNGrant) error {
	if e.closed {
		return errors.New("closed")
	}
	e.calls++
	e.grants[g.ID] = g
	return nil
}
func (e *fakeEngine) Usage(id string) (nodewire.VPNUsage, error) {
	g, ok := e.grants[id]
	if !ok {
		return nodewire.VPNUsage{}, errors.New("absent")
	}
	return nodewire.VPNUsage{GrantID: id, InstanceEpoch: e.epoch, Generation: g.Generation, Active: g.Enabled}, nil
}
func (e *fakeEngine) Epoch() string { return e.epoch }
func (e *fakeEngine) Close() error  { e.closed = true; return nil }
func fixture(t *testing.T) (Config, *nodecontrol.Signer, **fakeEngine) {
	t.Helper()
	raw, _ := nodecontrol.GenerateSigner()
	s, _ := nodecontrol.LoadSigner(raw)
	pub, _ := nodecontrol.LoadPublicKey(s.PublicPEM())
	var engine *fakeEngine
	n := 0
	cfg := Config{StateDir: filepath.Join(t.TempDir(), "owned"), NodeID: "11111111-1111-4111-8111-111111111111", InstallationID: "22222222-2222-4222-8222-222222222222", ConfigSHA256: strings.Repeat("a", 64), Signer: pub, Initialize: true, Factory: func() (Engine, error) {
		n++
		epoch := strings.Repeat("a", 32)
		if n > 1 {
			epoch = strings.Repeat("b", 32)
		}
		engine = &fakeEngine{epoch: epoch, grants: map[string]nodewire.VPNGrant{}}
		return engine, nil
	}}
	return cfg, s, &engine
}
func policy(cfg Config, epoch string, generation int64) nodewire.VPNPolicy {
	now := time.Now().UTC()
	return nodewire.VPNPolicy{SchemaVersion: 1, NodeID: cfg.NodeID, InstallationID: cfg.InstallationID, EngineEpoch: epoch, AuthorityEpoch: 1, Generation: generation, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Grants: []nodewire.VPNGrant{{ID: "33333333-3333-4333-8333-333333333333", Generation: generation, Enabled: true, Credential: "44444444-4444-4444-8444-444444444444", ExpiresAt: now.Add(time.Minute)}}}
}
func sign(t *testing.T, s *nodecontrol.Signer, p nodewire.VPNPolicy) nodewire.SignedVPNPolicy {
	t.Helper()
	v, e := s.SignVPN(p)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestDurablePolicyRestartRequiresFreshEngineEpoch(t *testing.T) {
	cfg, s, engine := fixture(t)
	c, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	p := policy(cfg, c.Epoch(), 1)
	signed := sign(t, s, p)
	receipt, e := c.Apply(signed)
	if e != nil {
		t.Fatal(e)
	}
	calls := (*engine).calls
	receipt.Usage[0].Active = false
	repeat, e := c.Apply(signed)
	if e != nil || !repeat.Usage[0].Active || (*engine).calls != calls {
		t.Fatal("retry re-applied or mutable receipt")
	}
	if _, e := Open(cfg); e == nil {
		t.Fatal("second process adopted engine directory")
	}
	c.Close()
	reopened, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if len((*engine).grants) != 0 {
		t.Fatal("restart resurrected saved grant")
	}
	if _, e = reopened.Apply(signed); e == nil {
		t.Fatal("prior engine epoch accepted")
	}
	p = policy(cfg, reopened.Epoch(), 1)
	if _, e = reopened.Apply(sign(t, s, p)); e == nil {
		t.Fatal("same generation rebound to new process")
	}
	p = policy(cfg, reopened.Epoch(), 2)
	if _, e = reopened.Apply(sign(t, s, p)); e != nil {
		t.Fatal(e)
	}
	p = policy(cfg, reopened.Epoch(), 3)
	p.Grants = []nodewire.VPNGrant{}
	if _, e = reopened.Apply(sign(t, s, p)); e != nil {
		t.Fatal(e)
	}
	for _, g := range (*engine).grants {
		if g.Enabled {
			t.Fatal("complete snapshot failed to deny missing grant")
		}
	}
}
func TestAmbiguousPersistClosesEngineAndRequiresReadback(t *testing.T) {
	cfg, s, engine := fixture(t)
	c, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	p := policy(cfg, c.Epoch(), 1)
	c.persist = func(fd int, state localState) error {
		if e := writeState(fd, state); e != nil {
			return e
		}
		return errors.New("fsync ambiguous")
	}
	if _, e = c.Apply(sign(t, s, p)); e == nil || !(*engine).closed || (*engine).calls != 0 {
		t.Fatal("effect before durable acceptance")
	}
	if _, e = c.Apply(sign(t, s, p)); e == nil {
		t.Fatal("poisoned instance retried")
	}
	c.Close()
	next, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if next.state.Generation != 1 || len((*engine).grants) != 0 {
		t.Fatal("committed state not read back safely")
	}
}
func TestBindingClockAndForeignDirectoryDenied(t *testing.T) {
	cfg, s, engine := fixture(t)
	c, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	p := policy(cfg, c.Epoch(), 1)
	signed := sign(t, s, p)
	c.now = func() time.Time { return time.Now().Add(-time.Hour) }
	if _, e = c.Apply(signed); e == nil || !(*engine).closed {
		t.Fatal("clock rollback")
	}
	c.Close()
	wrong := cfg
	wrong.InstallationID = "99999999-9999-4999-8999-999999999999"
	if _, e = Open(wrong); e == nil {
		t.Fatal("foreign binding")
	}
	if e = os.WriteFile(filepath.Join(cfg.StateDir, "foreign-service.conf"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(cfg); e == nil {
		t.Fatal("foreign directory adopted")
	}
}

func TestSmallClockCorrectionKeepsPolicyAndWatermark(t *testing.T) {
	cfg, s, engine := fixture(t)
	c, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := policy(cfg, c.Epoch(), 1)
	if _, err = c.Apply(sign(t, s, p)); err != nil {
		t.Fatal(err)
	}
	floor := c.state.WallHighWater
	c.now = func() time.Time { return time.Now().UTC().Add(-300 * time.Millisecond) }
	p.Generation++
	p.Grants[0].Generation++
	receipt, err := c.Apply(sign(t, s, p))
	if err != nil || (*engine).closed {
		t.Fatalf("small synchronization correction closed policy: %v", err)
	}
	if receipt.CompletedAt.Before(floor) || c.state.WallHighWater.Before(floor) {
		t.Fatal("persisted time or receipt moved backwards")
	}
	observed, err := c.ObservedAt()
	if err != nil || observed.Before(receipt.CompletedAt) || !observed.After(c.now()) {
		t.Fatal("corrected report time precedes its receipt")
	}
	c.now = func() time.Time { return time.Now().UTC().Add(-1200 * time.Millisecond) }
	p.Generation++
	p.Grants[0].Generation++
	if _, err = c.Apply(sign(t, s, p)); err == nil || !(*engine).closed {
		t.Fatal("rollback outside synchronization budget kept access")
	}
}

func TestRestartStillRejectsWallBelowPersistedFloor(t *testing.T) {
	cfg, _, _ := fixture(t)
	c, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The in-process correction allowance must never become a restart allowance.
	c.state.WallHighWater = time.Now().UTC().Add(500 * time.Millisecond)
	if err = writeState(c.dir, c.state); err != nil {
		t.Fatal(err)
	}
	c.Close()
	reopened, err := Open(cfg)
	if reopened != nil {
		reopened.Close()
	}
	if err == nil || err.Error() != "vpn_clock_untrusted" {
		t.Fatalf("restart bypassed persisted time floor: %v", err)
	}
}

func TestAmbiguousReceiptPersistStopsAlreadyAppliedEngine(t *testing.T) {
	cfg, s, engine := fixture(t)
	c, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	p := policy(cfg, c.Epoch(), 1)
	writes := 0
	c.persist = func(fd int, state localState) error {
		writes++
		if e := writeState(fd, state); e != nil {
			return e
		}
		if writes == 2 {
			return errors.New("receipt fsync ambiguous")
		}
		return nil
	}
	if _, e = c.Apply(sign(t, s, p)); e == nil || !(*engine).closed || (*engine).calls != 1 {
		t.Fatal("ambiguous receipt retained active engine")
	}
	c.Close()
	reopened, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if reopened.state.Receipt == nil || len((*engine).grants) != 0 {
		t.Fatal("receipt lost or restored access without fresh policy")
	}
}

func TestBackendAndProviderProfileAreSignedAndFenced(t *testing.T) {
	cfg, s, engine := fixture(t)
	cfg.Backend = "olcrtc"
	cfg.ProfileSHA256 = strings.Repeat("c", 64)
	c, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	p := policy(cfg, c.Epoch(), 1)
	if _, e = c.Apply(sign(t, s, p)); e == nil {
		t.Fatal("cross-backend policy applied")
	}
	p.Backend = "olcrtc"
	p.ProfileSHA256 = strings.Repeat("d", 64)
	p.Grants[0].Credential = strings.Repeat("a", 64)
	if _, e = c.Apply(sign(t, s, p)); e == nil {
		t.Fatal("different room policy applied")
	}
	if (*engine).calls != 0 {
		t.Fatal("rejected policy reached engine")
	}
	p.ProfileSHA256 = cfg.ProfileSHA256
	if _, e = c.Apply(sign(t, s, p)); e != nil {
		t.Fatal(e)
	}
}

func TestFactoryFailureDoesNotCloseTypedNilEngine(t *testing.T) {
	cfg, _, _ := fixture(t)
	cfg.Factory = func() (Engine, error) { var e *fakeEngine; return e, errors.New("provider unavailable") }
	if c, e := Open(cfg); c != nil || e == nil || e.Error() != "vpn_engine_start_failed" {
		t.Fatal("factory failure not reported")
	}
	// Failure releases the ownership lock so an explicit retry can recover.
	cfg.Factory = func() (Engine, error) { return &fakeEngine{epoch: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, nil }
	c, e := Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
}
