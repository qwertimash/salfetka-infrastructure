package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
)

func TestManagedOneIdentityIsolationAndReplay(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	parent, cert := enrolled(t, f)
	_, otherCert := enrolled(t, f)
	server, _ := database.NewID()
	if e := f.tx(func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO infrastructure_servers(id,name) VALUES($1,'Managed fixture')", server); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "UPDATE nodes_registry SET server_id=$2 WHERE id=$1", parent.ID, server); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, "INSERT INTO server_nodes(server_id,node_id) VALUES($1,$2)", server, parent.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	req := []ManagedRequest{{Name: "Reality A", GroupID: access.DefaultGroupID, Enabled: true, Configuration: connection.Configuration{Public: connection.Spec{Template: connection.Reality, Version: 1, Host: "vpn.example.com", ListenIP: "0.0.0.0", ServerName: "target.example.com", RealityTarget: "target.example.com:443"}}}}
	second := req[0]
	second.Name = "Reality B"
	req = append(req, second)
	m := f.m(parent, "managed.batch")
	var batch ManagedBatch
	if e := f.tx(func(tx pgx.Tx) error {
		var e error
		batch, _, e = f.s.CreateManagedConnectionsTx(ctx, tx, m, req)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if len(batch.Connections) != 2 || batch.Connections[0].VPN.Endpoint.Port != 443 || batch.Connections[1].VPN.Endpoint.Port != 444 {
		t.Fatal("allocation", batch)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		again, replay, e := f.s.CreateManagedConnectionsTx(ctx, tx, m, req)
		if e == nil && (!replay || again.Connections[0].ID != batch.Connections[0].ID) {
			t.Error("retry created different connection")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		listed, e := f.s.ListTx(ctx, tx, 100, "")
		found := 0
		for _, n := range listed {
			if n.ID == parent.ID {
				t.Error("physical node offered as subscription connection")
			}
			if n.OwnerNodeID != nil && *n.OwnerNodeID == parent.ID {
				found++
			}
		}
		if found != 2 {
			t.Errorf("logical connections missing: %d", found)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	for _, c := range batch.Connections {
		var count int
		if e := f.p.QueryRow(ctx, "SELECT count(*) FROM nodes_registry WHERE id=$1 AND serial IS NULL AND public_key IS NULL AND owner_node_id=$2", c.ID, parent.ID).Scan(&count); e != nil || count != 1 {
			t.Fatal("logical slot has physical credentials", e)
		}
		var cipher []byte
		if e := f.p.QueryRow(ctx, "SELECT configuration_ciphertext FROM managed_connection_versions WHERE connection_id=$1", c.ID).Scan(&cipher); e != nil {
			t.Fatal(e)
		}
		if json.Valid(cipher) {
			t.Fatal("configuration persisted as plaintext")
		}
		raw, e := f.s.Vault.Open(cipher, managedAAD(c.ID, 1))
		if e != nil {
			t.Fatal(e)
		}
		var config connection.Configuration
		if json.Unmarshal(raw, &config) != nil || config.Validate() != nil {
			t.Fatal("invalid stored configuration")
		}
		clear(raw)
		if e = f.tx(func(tx pgx.Tx) error {
			_, _, e := f.s.EnrollmentTx(ctx, tx, f.m(Node{ID: c.ID, Revision: c.VPN.NodeRevision}, "enroll"))
			return e
		}); !errors.Is(e, ErrConflict) {
			t.Fatal("slot enrolled", e)
		}
	}
	boot, _ := database.NewID()
	if _, _, e := f.s.Heartbeat(ctx, cert, nodewire.HeartbeatRequest{SchemaVersion: 1, NodeID: parent.ID, BootID: boot, Sequence: 1, Version: "managed-test", Platform: "linux", Arch: "amd64", Capabilities: []string{"enrollment", "heartbeat", "certificate_renewal", "managed_connections_v1"}}); e != nil {
		t.Fatal(e)
	}
	signed, e := f.s.ConnectionsDesired(ctx, cert, parent.ID)
	if e != nil {
		t.Fatal(e)
	}
	pubManifest, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	plan, e := nodecontrol.VerifyConnections(pubManifest, signed)
	if e != nil || len(plan.Connections) != 2 {
		t.Fatal("manifest", e)
	}
	report := nodewire.ConnectionsReport{SchemaVersion: 1, NodeID: parent.ID, BootID: boot, Sequence: 1, PlanRevision: plan.Revision, States: []nodewire.ConnectionState{}}
	for _, c := range plan.Connections {
		report.States = append(report.States, nodewire.ConnectionState{ID: c.ID, Revision: c.Revision, State: "listening"})
	}
	if e = f.s.RecordConnections(ctx, cert, report); e != nil {
		t.Fatal(e)
	}
	assertStates := func(want string) {
		t.Helper()
		if err := f.tx(func(tx pgx.Tx) error {
			view, err := f.s.ManagedServerTx(ctx, tx, server)
			for _, c := range view.Connections {
				if c.RuntimeState != want {
					t.Errorf("runtime state %s, want %s", c.RuntimeState, want)
				}
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertStates("listening")
	newBoot, _ := database.NewID()
	if _, _, e = f.s.Heartbeat(ctx, cert, nodewire.HeartbeatRequest{SchemaVersion: 1, NodeID: parent.ID, BootID: newBoot, Sequence: 1, Version: "managed-test", Platform: "linux", Arch: "amd64", Capabilities: []string{"enrollment", "heartbeat", "certificate_renewal", "managed_connections_v1"}}); e != nil {
		t.Fatal(e)
	}
	assertStates("pending")
	if e = f.s.RecordConnections(ctx, cert, report); !errors.Is(e, ErrConflict) {
		t.Fatal("old boot report accepted", e)
	}
	report.BootID = newBoot
	if e = f.s.RecordConnections(ctx, cert, report); e != nil {
		t.Fatal(e)
	}
	assertStates("listening")
	if _, e = f.s.ConnectionsDesired(ctx, otherCert, parent.ID); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("private manifest leaked", e)
	}
	if e = f.tx(func(tx pgx.Tx) error {
		c := batch.Connections[0]
		request := ManagedUpdate{Request: ManagedRequest{Name: c.Name, GroupID: c.VPN.GroupID, Enabled: false, Configuration: connection.Configuration{Public: *c.VPN.Endpoint.Connection}}}
		changed, _, e := f.s.UpdateManagedConnectionTx(ctx, tx, f.m(Node{ID: c.ID, Revision: c.VPN.NodeRevision}, "managed.disable"), request)
		if e == nil {
			batch.Connections[0] = changed
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = f.tx(func(tx pgx.Tx) error {
		c := batch.Connections[0]
		changed, _, e := f.s.UpdateManagedConnectionTx(ctx, tx, f.m(Node{ID: c.ID, Revision: c.VPN.NodeRevision}, "managed.rollback"), ManagedUpdate{RollbackRevision: 1})
		if e == nil && changed.VPN.Enabled {
			t.Error("rollback re-enabled access")
		}
		if e == nil {
			batch.Connections[0] = changed
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// Re-enable deliberately for the independent access/revocation checks.
	if e = f.tx(func(tx pgx.Tx) error {
		c := batch.Connections[0]
		changed, _, e := f.s.UpdateManagedConnectionTx(ctx, tx, f.m(Node{ID: c.ID, Revision: c.VPN.NodeRevision}, "managed.enable"), ManagedUpdate{Request: ManagedRequest{Name: c.Name, GroupID: c.VPN.GroupID, Enabled: true, Configuration: connection.Configuration{Public: *c.VPN.Endpoint.Connection}}})
		if e == nil {
			batch.Connections[0] = changed
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	seedVPNUser(t, f)
	a, b := batch.Connections[0], batch.Connections[1]
	fetch := func(c ManagedConnection) VPNFetch {
		return VPNFetch{SchemaVersion: 1, NodeID: c.ID, InstallationID: c.VPN.InstallationID, EngineEpoch: strings.Repeat("a", 32), ProfileSHA256: c.VPN.Endpoint.ProfileSHA256()}
	}
	if _, _, e := f.s.VPNDesired(ctx, otherCert, fetch(a)); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("foreign physical certificate accessed connection", e)
	}
	desired, _, e := f.s.VPNDesired(ctx, cert, fetch(a))
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	policy, e := nodecontrol.VerifyVPN(pub, *desired.Policy)
	if e != nil || len(policy.Grants) != 1 || policy.ProfileSHA256 == "" {
		t.Fatal("managed policy", e)
	}
	bad := fetch(a)
	bad.ProfileSHA256 = ""
	if _, _, e = f.s.VPNDesired(ctx, cert, bad); e == nil {
		t.Fatal("unbound configuration got access")
	}
	if _, e = f.s.Desired(ctx, cert, a.ID); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("physical agent command delegated to connection", e)
	}
	if e = f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.RevokeTx(ctx, tx, f.m(Node{ID: a.ID, Revision: a.VPN.NodeRevision}, "revoke"))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.s.VPNDesired(ctx, cert, fetch(a)); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("revoked connection accepted", e)
	}
	if _, _, e = f.s.VPNDesired(ctx, cert, fetch(b)); e != nil {
		t.Fatal("A revocation broke B", e)
	}
	if e = f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.RevokeTx(ctx, tx, f.m(Node{ID: parent.ID, Revision: batch.NodeRevision}, "revoke-parent"))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.s.VPNDesired(ctx, cert, fetch(b)); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("parent revoke left B active", e)
	}
}

func TestManagedRegisterDoesNotDuplicateOrAdoptLegacy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var server Server
	if e := f.tx(func(tx pgx.Tx) error {
		var e error
		server, _, e = f.s.CreateServerTx(ctx, tx, f.m(Node{}, "servers"), "Managed fixture")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	m := f.m(Node{}, "register")
	var node Node
	if e := f.tx(func(tx pgx.Tx) error {
		var e error
		node, _, e = f.s.RegisterServerNodeTx(ctx, tx, m, server.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		again, replay, e := f.s.RegisterServerNodeTx(ctx, tx, m, server.ID)
		if e == nil && (!replay || again.ID != node.ID) {
			t.Error("lost response duplicate identity")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.RegisterServerNodeTx(ctx, tx, f.m(Node{}, "register"), server.ID)
		return e
	}); !errors.Is(e, ErrConflict) {
		t.Fatal("second physical node accepted", e)
	}
}
