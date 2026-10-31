package nodes

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"strings"
	"testing"
)

func TestManagedBackendIssuanceBindingAndPrivateExport(t *testing.T) {
	for _, backend := range []string{"hysteria2", "olcrtc"} {
		t.Run(backend, func(t *testing.T) {
			f := controlFixture(t)
			ctx := context.Background()
			n, cert := enrolled(t, f)
			install, _ := database.NewID()
			ep := VPNEndpoint{Backend: backend, Host: "vpn.example.invalid", Port: 14443, ServerName: "vpn.example.invalid"}
			if backend == "olcrtc" {
				ep = VPNEndpoint{Backend: backend, Provider: "jitsi", Transport: "vp8channel", Room: "https://room.example.invalid/test", BootstrapDNS: "1.1.1.1:53"}
			}
			m := f.m(n, "b8-configure")
			var configured VPNInstallation
			if e := f.tx(func(tx pgx.Tx) error {
				var e error
				configured, _, e = f.s.ConfigureVPNTx(ctx, tx, m, install, access.DefaultGroupID, true, &ep)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			user, grant := seedVPNUser(t, f)
			request := VPNFetch{Backend: backend, ProfileSHA256: ep.ProfileSHA256(), SchemaVersion: 1, NodeID: n.ID, InstallationID: install, EngineEpoch: strings.Repeat("a", 32)}
			bad := request
			bad.Backend = ""
			if _, _, e := f.s.VPNDesired(ctx, cert, bad); e == nil {
				t.Fatal("backend mismatch issued")
			}
			if backend == "olcrtc" {
				bad = request
				bad.ProfileSHA256 = strings.Repeat("b", 64)
				if _, _, e := f.s.VPNDesired(ctx, cert, bad); e == nil {
					t.Fatal("room mismatch issued")
				}
			}
			out, _, e := f.s.VPNDesired(ctx, cert, request)
			if e != nil {
				t.Fatal(e)
			}
			pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
			policy, e := nodecontrol.VerifyVPN(pub, *out.Policy)
			if e != nil || len(policy.Grants) != 1 || policy.Grants[0].ID != grant || policy.Backend != backend || policy.ProfileSHA256 != ep.ProfileSHA256() {
				t.Fatal("wrong policy binding", e)
			}
			var device string
			if e = f.p.QueryRow(ctx, "SELECT id::text FROM access_devices WHERE user_id=$1", user).Scan(&device); e != nil {
				t.Fatal(e)
			}
			if e = f.tx(func(tx pgx.Tx) error {
				_, key, e := access.New(f.p, f.s.Vault).VPNCredentialTx(ctx, tx, user, device, n.ID, access.DefaultGroupID, backend)
				if e != nil {
					return e
				}
				if key != policy.Grants[0].Credential {
					t.Fatal("published key differs from applied key")
				}
				if !json.Valid(ClientConfig(ep, key)) {
					t.Fatal("config malformed")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			n.Revision = configured.NodeRevision
			m = f.m(n, "b8-switch-denied")
			ep.Backend = ""
			if e = f.tx(func(tx pgx.Tx) error {
				_, _, e := f.s.ConfigureVPNTx(ctx, tx, m, install, access.DefaultGroupID, true, &ep)
				return e
			}); e == nil {
				t.Fatal("installation changed backend")
			}
		})
	}
}
