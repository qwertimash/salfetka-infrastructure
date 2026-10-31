package nodes

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/bypasslease"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
)

func TestBypassCoordinatorAuthenticatesEveryTransaction(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	id := func() string {
		s, e := database.NewID()
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	install := id()
	epoch := strings.Repeat("a", 32)
	ep := VPNEndpoint{AccountSession: true, Backend: "olcrtc", Provider: "jitsi", Transport: "vp8channel", Room: "https://room.example.invalid/test", BootstrapDNS: "1.1.1.1:53"}
	if e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.ConfigureVPNTx(ctx, tx, f.m(n, "session-install"), install, access.DefaultGroupID, true, &ep)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	user, grant := seedVPNUser(t, f)
	if _, _, e := f.s.VPNDesired(ctx, cert, VPNFetch{SchemaVersion: 1, NodeID: n.ID, InstallationID: install, EngineEpoch: epoch, Backend: "olcrtc", ProfileSHA256: ep.ProfileSHA256()}); e != nil {
		t.Fatal(e)
	}
	q := nodewire.BypassRequest{SchemaVersion: 1, NodeID: n.ID, InstallationID: install, EngineEpoch: epoch, Nonce: id(), Operation: "claim", CredentialID: grant, RequestID: id()}
	if _, e := f.s.BypassSession(ctx, nil, q); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("unauthenticated claim", e)
	}
	first, e := f.s.BypassSession(ctx, cert, q)
	if e != nil || first.Code != "" || first.State != "pending" || first.UserID != user || first.Nonce != q.Nonce {
		t.Fatal(first, e)
	}
	duplicate, e := f.s.BypassSession(ctx, cert, q)
	if e != nil || duplicate.Generation != first.Generation {
		t.Fatal("duplicate claim", e)
	}
	q.UserID = first.UserID
	q.Generation = first.Generation
	q.RequestID = ""
	q.Operation = "activate"
	active, e := f.s.BypassSession(ctx, cert, q)
	if e != nil || active.Code != "" || active.State != "active" || active.RemainingMS <= 0 || active.RemainingMS > 30000 {
		t.Fatal(active, e)
	}
	wrong := q
	wrong.EngineEpoch = strings.Repeat("b", 32)
	out, e := f.s.BypassSession(ctx, cert, wrong)
	if e != nil || out.Code != bypasslease.ErrDenied.Error() {
		t.Fatal("foreign epoch", out, e)
	}
	q.Operation = "renew"
	q.Revision = active.Revision
	if _, e = f.p.Exec(ctx, `UPDATE nodes_registry SET state='revoked' WHERE id=$1`, n.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.BypassSession(ctx, cert, q); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("live cert revocation bypass", e)
	}
	var revision int64
	if e = f.p.QueryRow(ctx, `SELECT revision FROM bypass_leases WHERE user_id=$1`, user).Scan(&revision); e != nil || revision != active.Revision {
		t.Fatal("unauthorized mutation", e)
	}
}
