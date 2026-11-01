package nodevpn

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"sync/atomic"
	"testing"
	"time"
)

type fleetFake struct {
	stopped atomic.Bool
	epoch   string
}

func TestFleetRestartHonorsPersistedClockFloor(t *testing.T) {
	for _, gap := range []time.Duration{150 * time.Millisecond, 2 * time.Second} {
		t.Run(gap.String(), func(t *testing.T) {
			key, _ := nodecontrol.GenerateSigner()
			signer, _ := nodecontrol.LoadSigner(key)
			pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
			cfg := FleetConfig{StateDir: filepath.Join(t.TempDir(), "fleet"), NodeID: "00000000-0000-4000-8000-000000000001", Signer: pub, Initialize: true,
				Open: func(nodewire.ConnectionDeployment, string, bool) (FleetController, error) {
					t.Fatal("restart must not start saved listeners")
					return nil, errors.New("unexpected listener")
				}}
			f, err := OpenFleet(cfg)
			if err != nil {
				t.Fatal(err)
			}
			watermark := time.Now().UTC().Add(gap)
			f.mu.Lock()
			f.state.WallHighWater = watermark
			err = writeStateValue(f.dir, f.state)
			f.mu.Unlock()
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Initialize = false
			f, err = OpenFleet(cfg)
			if gap > time.Second {
				if f != nil {
					f.Close()
				}
				if err == nil || err.Error() != "fleet_clock_untrusted" {
					t.Fatal("large rollback accepted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if time.Now().Before(watermark) || !f.state.WallHighWater.Equal(watermark) {
				t.Fatal("restart bypassed persisted clock floor")
			}
		})
	}
}

func TestFleetEmptyPlanProducesExplicitEmptyWireReport(t *testing.T) {
	key, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(key)
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	id := "00000000-0000-4000-8000-000000000001"
	f, err := OpenFleet(FleetConfig{StateDir: filepath.Join(t.TempDir(), "fleet"), NodeID: id, Signer: pub, Initialize: true, Open: func(nodewire.ConnectionDeployment, string, bool) (FleetController, error) {
		t.Fatal("empty plan must not start a listener")
		return nil, errors.New("unexpected listener")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for range 2 {
		now := time.Now().UTC()
		signed, err := signer.SignConnections(nodewire.ConnectionsPlan{SchemaVersion: 1, NodeID: id, Revision: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Connections: []nodewire.ConnectionDeployment{}})
		if err != nil {
			t.Fatal(err)
		}
		states, err := f.Apply(signed)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(nodewire.ConnectionsReport{States: states})
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err = json.Unmarshal(raw, &wire); err != nil || string(wire["states"]) != "[]" {
			t.Fatalf("empty report rejected by wire contract: %s, %v", raw, err)
		}
	}
}

func (f *fleetFake) Epoch() string { return f.epoch }
func (f *fleetFake) Apply(nodewire.SignedVPNPolicy) (nodewire.VPNReceipt, error) {
	return nodewire.VPNReceipt{}, nil
}
func (f *fleetFake) Usage() ([]nodewire.VPNUsage, error) { return nil, nil }
func (f *fleetFake) ObservedAt() (time.Time, error)      { return time.Now(), nil }
func (f *fleetFake) Close()                              { f.stopped.Store(true) }
func fleetDeployment(t *testing.T, id string, port int) nodewire.ConnectionDeployment {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c := connection.Configuration{Public: connection.Spec{Template: connection.Reality, Version: 1, Host: "vpn.example.com", ListenIP: "127.0.0.1", Port: port, ServerName: "target.example.com", RealityTarget: "target.example.com:443", RealityPublicKey: base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), RealityShortID: "1234"}, Private: connection.PrivateMaterial{RealityPrivateKey: base64.RawURLEncoding.EncodeToString(k.Bytes())}}
	return nodewire.ConnectionDeployment{ID: id, InstallationID: id, Revision: 1, Enabled: true, Configuration: c, ConfigurationSHA256: connection.Hash(c)}
}
func TestFleetIndependentReplacementRestartReplayAndStorageFailure(t *testing.T) {
	key, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(key)
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	node := "00000000-0000-4000-8000-000000000001"
	a := fleetDeployment(t, "00000000-0000-4000-8000-000000000002", 2443)
	b := fleetDeployment(t, "00000000-0000-4000-8000-000000000003", 2444)
	var created []*fleetFake
	cfg := FleetConfig{StateDir: filepath.Join(t.TempDir(), "fleet"), NodeID: node, Signer: pub, Initialize: true, Open: func(c nodewire.ConnectionDeployment, _ string, _ bool) (FleetController, error) {
		if c.Configuration.Public.Port == 9999 {
			return nil, errors.New("port occupied")
		}
		f := &fleetFake{epoch: c.ID}
		created = append(created, f)
		return f, nil
	}}
	f, e := OpenFleet(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { f.Close() }()
	plan := nodewire.ConnectionsPlan{SchemaVersion: 1, NodeID: node, Revision: 1, IssuedAt: time.Now().UTC().Add(-time.Second), ExpiresAt: time.Now().UTC().Add(time.Minute), Connections: []nodewire.ConnectionDeployment{a, b}}
	sign := func() nodewire.SignedConnectionsPlan {
		t.Helper()
		s, e := signer.SignConnections(plan)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	first := sign()
	status, e := f.Apply(first)
	if e != nil || len(status) != 2 || len(created) != 2 {
		t.Fatal("first apply", e)
	}
	if _, e = f.Apply(first); e != nil || len(created) != 2 {
		t.Fatal("retry restarted engines", e)
	}
	oldA, oldB := created[0], created[1]
	plan.Revision++
	plan.Connections[0].Revision++
	plan.Connections[0].Configuration.Public.Port = 9999
	plan.Connections[0].ConfigurationSHA256 = connection.Hash(plan.Connections[0].Configuration)
	status, e = f.Apply(sign())
	if e != nil || status[0].State != "failed" || !oldA.stopped.Load() || oldB.stopped.Load() {
		t.Fatal("A failure affected B", e)
	}
	if _, e = f.Apply(first); e == nil {
		t.Fatal("old desired resurrected A")
	}
	f.Close()
	if !oldB.stopped.Load() {
		t.Fatal("shutdown left B")
	}
	cfg.Initialize = false
	f, e = OpenFleet(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if len(f.Bindings()) != 0 {
		t.Fatal("restart applied saved access")
	}
	if _, e = f.Apply(first); e == nil {
		t.Fatal("restart lost watermark")
	}
	plan.Revision++
	plan.Connections[0].Revision++
	plan.Connections[0].Configuration.Public.Port = 2443
	plan.Connections[0].ConfigurationSHA256 = connection.Hash(plan.Connections[0].Configuration)
	if _, e = f.Apply(sign()); e != nil || len(f.Bindings()) != 2 {
		t.Fatal("recovery", e)
	}
	f.persist = func(int, any) error { return errors.New("disk failed") }
	plan.Revision++
	if _, e = f.Apply(sign()); e == nil || len(f.Bindings()) != 0 {
		t.Fatal("failed persist continued serving")
	}
}
func TestFleetPlanExpiryStopsListenersWithoutPolling(t *testing.T) {
	key, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(key)
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	node := "00000000-0000-4000-8000-000000000001"
	engine := &fleetFake{epoch: "first"}
	f, e := OpenFleet(FleetConfig{StateDir: filepath.Join(t.TempDir(), "fleet"), NodeID: node, Signer: pub, Initialize: true, Open: func(nodewire.ConnectionDeployment, string, bool) (FleetController, error) { return engine, nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	p := nodewire.ConnectionsPlan{SchemaVersion: 1, NodeID: node, Revision: 1, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(150 * time.Millisecond), Connections: []nodewire.ConnectionDeployment{fleetDeployment(t, "00000000-0000-4000-8000-000000000002", 2443)}}
	signed, e := signer.SignConnections(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Apply(signed); e != nil {
		t.Fatal(e)
	}
	until := time.Now().Add(2 * time.Second)
	for !engine.stopped.Load() && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if !engine.stopped.Load() {
		t.Fatal("expired manifest kept listener")
	}
}
