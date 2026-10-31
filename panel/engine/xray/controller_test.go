package xrayengine

import (
	"path/filepath"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodevpn"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

func TestOwnedControllerRealEngineRestartAndSignedRevoke(t *testing.T) {
	ca := syntheticCert(t)
	port := freePort(t, false)
	tcp, udp := echoes(t)
	raw, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(raw)
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	cfg := nodevpn.Config{StateDir: filepath.Join(t.TempDir(), "engine"), NodeID: "77777777-7777-4777-8777-777777777777", InstallationID: "88888888-8888-4888-8888-888888888888", ConfigSHA256: strings.Repeat("f", 64), Signer: pub, Initialize: true, Factory: func() (nodevpn.Engine, error) {
		return New(Config{ListenIP: "127.0.0.1", Port: port, CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n"), LabLoopbackOnly: true})
	}}
	c, err := nodevpn.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	now := time.Now().UTC()
	p := nodewire.VPNPolicy{SchemaVersion: 1, NodeID: cfg.NodeID, InstallationID: cfg.InstallationID, EngineEpoch: c.Epoch(), AuthorityEpoch: 1, Generation: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Grants: []nodewire.VPNGrant{{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: now.Add(time.Minute)}, {ID: users[1].Secret, Generation: 1, Enabled: true, Credential: users[1].Secret, ExpiresAt: now.Add(time.Minute)}}}
	signed, err := signer.SignVPN(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Apply(signed); err != nil {
		t.Fatal(err)
	}
	a, b := startClient(t, "vless_tls", port, ca, users[0]), startClient(t, "vless_tls", port, ca, users[1])
	at, au := openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
	bt, bu := openFlow(t, b, "tcp", tcp), openFlow(t, b, "udp", udp)
	check(t, at.exchange([]byte("signed-A")) && au.exchange([]byte("signed-UDP-A")) && bt.exchange([]byte("signed-B")) && bu.exchange([]byte("signed-UDP-B")), "signed grants did not connect")
	measured, err := c.Usage()
	if err != nil || len(measured) != 2 || measured[0].Uplink == nil || *measured[0].Uplink == 0 {
		t.Fatal("actual usage missing")
	}
	p.Generation = 2
	p.Grants = p.Grants[1:]
	p.Grants[0].Generation = 2
	signed, err = signer.SignVPN(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Apply(signed); err != nil {
		t.Fatal(err)
	}
	check(t, !at.exchange([]byte("denied-A")) && !au.exchange([]byte("denied-UDP-A")) && !one(t, a, "tcp", tcp), "complete desired snapshot failed to revoke A")
	check(t, bt.exchange([]byte("surviving-B")) && bu.exchange([]byte("surviving-UDP-B")), "signed revoke disrupted B")
	oldEpoch := c.Epoch()
	c.Close()
	next, err := nodevpn.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	check(t, next.Epoch() != oldEpoch, "engine epoch survived recreation")
	if _, err = next.Apply(signed); err == nil {
		t.Fatal("saved policy revived new process")
	}
	check(t, !one(t, b, "tcp", tcp), "saved B config connected before fresh authorization")
	p.EngineEpoch = next.Epoch()
	p.Generation = 3
	p.Grants[0].Generation = 3
	signed, err = signer.SignVPN(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = next.Apply(signed); err != nil {
		t.Fatal(err)
	}
	check(t, one(t, b, "tcp", tcp) && one(t, b, "udp", udp) && !one(t, a, "tcp", tcp), "fresh policy failed to restore only B")
	t.Log("owned persistent controller + real Xray: signed apply, actual counters, A revoke/B preservation, new engine epoch rejects saved policy, fresh generation restores B")
}

func TestBootClockStepRequiresNewEngineAndFreshAuthorization(t *testing.T) {
	ca := syntheticCert(t)
	port := freePort(t, false)
	tcp, udp := echoes(t)
	raw, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(raw)
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	var runtime *Runtime
	cfg := nodevpn.Config{StateDir: filepath.Join(t.TempDir(), "engine"), NodeID: "77777777-7777-4777-8777-777777777777", InstallationID: "88888888-8888-4888-8888-888888888888", ConfigSHA256: strings.Repeat("f", 64), Signer: pub, Initialize: true, Factory: func() (nodevpn.Engine, error) {
		var e error
		runtime, e = New(Config{ListenIP: "127.0.0.1", Port: port, CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n"), LabLoopbackOnly: true})
		return runtime, e
	}}
	c, e := nodevpn.Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	// Steps outside the synchronization budget still require a new engine and
	// fresh authorization. Subsecond synchronization is covered separately.
	runtime.mu.Lock()
	runtime.now = func() time.Time { return time.Now().Add(-1205 * time.Millisecond) }
	runtime.checkClockLocked(runtime.now())
	runtime.now = time.Now
	runtime.mu.Unlock()
	now := time.Now().UTC()
	p := nodewire.VPNPolicy{SchemaVersion: 1, NodeID: cfg.NodeID, InstallationID: cfg.InstallationID, EngineEpoch: c.Epoch(), AuthorityEpoch: 1, Generation: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Grants: []nodewire.VPNGrant{{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: now.Add(time.Minute)}}}
	signed, _ := signer.SignVPN(p)
	if _, e = c.Apply(signed); e == nil || e.Error() != "vpn_engine_clock_untrusted" {
		t.Fatalf("boot failure not reproduced: %v", e)
	}
	c.Close()
	next, e := nodevpn.Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	a := startClient(t, "vless_tls", port, ca, users[0])
	if _, e = next.Apply(signed); e == nil {
		t.Fatal("saved policy revived a new engine")
	}
	check(t, !one(t, a, "tcp", tcp) && !one(t, a, "udp", udp), "clock recovery restored access without authorization")
	p.EngineEpoch = next.Epoch()
	p.Generation = 2
	p.Grants = []nodewire.VPNGrant{}
	revoked, _ := signer.SignVPN(p)
	if _, e = next.Apply(revoked); e != nil {
		t.Fatal(e)
	}
	check(t, !one(t, a, "tcp", tcp), "revoked A revived during recovery")
	p.Generation = 3
	p.Grants = []nodewire.VPNGrant{{ID: users[1].Secret, Generation: 3, Enabled: true, Credential: users[1].Secret, ExpiresAt: now.Add(time.Minute)}}
	fresh, _ := signer.SignVPN(p)
	if _, e = next.Apply(fresh); e != nil {
		t.Fatal(e)
	}
	b := startClient(t, "vless_tls", port, ca, users[1])
	check(t, one(t, b, "tcp", tcp) && one(t, b, "udp", udp) && !one(t, a, "tcp", tcp), "fresh authorized B or revoked A incorrect")
	t.Log("205ms boot clock step reproduced; old engine poisoned and closed; new epoch rejects saved policy, current revocation preserved, fresh B TCP/UDP restored")
}
