package xrayengine

import (
	"path/filepath"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodevpn"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

func TestFleetRealMixedTransportsIndependentEditAndRestart(t *testing.T) {
	ca := syntheticCert(t)
	tcp, udp := echoes(t)
	key, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(key)
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	parent := "77777777-7777-4777-8777-777777777777"
	configs := []nodewire.ConnectionDeployment{}
	for i, kind := range []string{connection.GRPC, connection.XHTTP, connection.Hy2} {
		id := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}[i]
		c := connection.Configuration{Public: connection.Spec{Template: kind, Version: 1, Host: "127.0.0.1", ListenIP: "127.0.0.1", Port: freePort(t, kind == connection.Hy2), ServerName: "b0.invalid"}, Private: connection.PrivateMaterial{CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n")}}
		if kind == connection.GRPC {
			c.Public.ServiceName = "vpn"
		}
		if kind == connection.XHTTP {
			c.Public.Path = "/vpn"
		}
		configs = append(configs, nodewire.ConnectionDeployment{ID: id, InstallationID: id, Revision: 1, Enabled: true, Configuration: c, ConfigurationSHA256: connection.Hash(c)})
	}
	cfg := nodevpn.FleetConfig{StateDir: filepath.Join(t.TempDir(), "fleet"), NodeID: parent, Signer: pub, Initialize: true, Open: func(d nodewire.ConnectionDeployment, dir string, initialize bool) (nodevpn.FleetController, error) {
		backend := ""
		if d.Configuration.Public.Template == connection.Hy2 {
			backend = "hysteria2"
		}
		return nodevpn.Open(nodevpn.Config{Backend: backend, ProfileSHA256: connection.ProfileHash(d.Configuration.Public), NodeID: d.ID, InstallationID: d.InstallationID, ConfigSHA256: d.ConfigurationSHA256, Signer: pub, StateDir: dir, Initialize: initialize, Factory: func() (nodevpn.Engine, error) {
			return New(Config{Connection: &d.Configuration, LabLoopbackOnly: true})
		}})
	}}
	fleet, e := nodevpn.OpenFleet(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { fleet.Close() }()
	p := nodewire.ConnectionsPlan{SchemaVersion: 1, NodeID: parent, Revision: 1, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute), Connections: configs}
	applyPlan := func() {
		t.Helper()
		signed, e := signer.SignConnections(p)
		if e != nil {
			t.Fatal(e)
		}
		states, e := fleet.Apply(signed)
		if e != nil {
			t.Fatal(e)
		}
		for _, s := range states {
			if s.State != "listening" {
				t.Fatal("mixed runtime start failed", s.State)
			}
		}
	}
	authorize := func(generation int64) {
		t.Helper()
		for _, b := range fleet.Bindings() {
			backend := ""
			if b.Deployment.Configuration.Public.Template == connection.Hy2 {
				backend = "hysteria2"
			}
			now := time.Now().UTC()
			policy := nodewire.VPNPolicy{SchemaVersion: 1, Backend: backend, ProfileSHA256: connection.ProfileHash(b.Deployment.Configuration.Public), NodeID: b.Deployment.ID, InstallationID: b.Deployment.InstallationID, EngineEpoch: b.Epoch, AuthorityEpoch: 1, Generation: generation, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Grants: []nodewire.VPNGrant{{ID: users[0].Secret, Generation: generation, Enabled: true, Credential: users[0].Secret, ExpiresAt: now.Add(time.Minute)}}}
			signed, e := signer.SignVPN(policy)
			if e != nil {
				t.Fatal(e)
			}
			e = fleet.WithConnection(b.Deployment.ID, b.Epoch, func(c nodevpn.FleetController) error { _, e := c.Apply(signed); return e })
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	client := func(d nodewire.ConnectionDeployment) *engine {
		out, e := d.Configuration.Public.ClientOutbound(users[0].Secret, strings.Join(ca.root, "\n"))
		if e != nil {
			t.Fatal(e)
		}
		return startEngine(t, map[string]any{"outbounds": []any{out}})
	}
	applyPlan()
	authorize(1)
	clients := []*engine{}
	flows := []*flow{}
	for _, c := range configs {
		x := client(c)
		clients = append(clients, x)
		f := openFlow(t, x, "tcp", tcp)
		flows = append(flows, f)
		check(t, f.exchange([]byte("mixed TCP")) && one(t, x, "udp", udp), "mixed real traffic failed")
	}
	before := map[string]string{}
	for _, b := range fleet.Bindings() {
		before[b.Deployment.ID] = b.Epoch
	}
	// Change only the gRPC listener. Existing XHTTP and Hy2 flows must survive.
	p.Revision++
	p.Connections[0].Revision++
	p.Connections[0].Configuration.Public.Port = freePort(t, false)
	p.Connections[0].ConfigurationSHA256 = connection.Hash(p.Connections[0].Configuration)
	applyPlan()
	authorize(2)
	for _, b := range fleet.Bindings() {
		if b.Deployment.ID != p.Connections[0].ID && before[b.Deployment.ID] != b.Epoch {
			t.Fatal("unrelated engine restarted")
		}
	}
	check(t, !flows[0].exchange([]byte("old A")), "edited listener retained old session")
	check(t, flows[1].exchange([]byte("B survives")) && flows[2].exchange([]byte("Hy2 survives")), "A edit broke B")
	newA := client(p.Connections[0])
	check(t, one(t, newA, "tcp", tcp) && one(t, newA, "udp", udp), "new A config failed")
	fleet.Close()
	cfg.Initialize = false
	fleet, e = nodevpn.OpenFleet(cfg)
	if e != nil {
		t.Fatal(e)
	}
	check(t, len(fleet.Bindings()) == 0, "restart silently restored access")
	applyPlan()
	authorize(3)
	check(t, one(t, newA, "tcp", tcp) && one(t, clients[1], "tcp", tcp) && one(t, clients[2], "udp", udp), "restart/fresh authorization failed")
}
