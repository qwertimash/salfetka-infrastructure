package bypasslease

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database/dbtest"
	"strings"
	"testing"
)

func TestRestartFenceOnlyClosesPriorOwnedEngine(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	a, b := owner(t, p, u), owner(t, p, u)
	old := active(t, s, a)
	pending, e := s.ClaimExplicit(ctx, b, id(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Activate(ctx, b, pending.Ref); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if e = s.AcknowledgePreviousEngine(ctx, a); !errors.Is(e, ErrDenied) {
		t.Fatal("untrusted fence", e)
	}
	current := a
	current.EngineEpoch = strings.Repeat("f", 32)
	exec(t, p, `UPDATE nodes_vpn_installations SET engine_epoch=$2 WHERE node_id=$1`, a.NodeID, current.EngineEpoch)
	trusted := Authenticated(p, func(context.Context, pgx.Tx, Owner) error { return nil }) // machine auth is tested in nodes/httpapi
	if e = trusted.AcknowledgePreviousEngine(ctx, a); !errors.Is(e, ErrDenied) {
		t.Fatal("stale epoch fenced", e)
	}
	for i := 0; i < 2; i++ {
		if e = trusted.AcknowledgePreviousEngine(ctx, current); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.Activate(ctx, b, pending.Ref); e != nil {
		t.Fatal("foreign pending lost", e)
	}
	if _, e = s.Renew(ctx, a, old.Ref, old.Revision); !errors.Is(e, ErrDenied) {
		t.Fatal("old process returned", e)
	}
	if e = trusted.AcknowledgePreviousEngine(ctx, current); e != nil {
		t.Fatal(e)
	}
	l, e := s.Status(ctx, b, pending.Ref)
	if e != nil || l.State != "active" {
		t.Fatal("other installation fenced", e)
	}
}

func TestRestartFenceResumesOnlyLatestIntent(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	old := owner(t, p, u)
	request := id(t)
	l, e := s.ClaimExplicit(ctx, old, request)
	if e != nil {
		t.Fatal(e)
	}
	l, e = s.Activate(ctx, old, l.Ref)
	if e != nil {
		t.Fatal(e)
	}
	current := old
	current.EngineEpoch = strings.Repeat("e", 32)
	exec(t, p, `UPDATE nodes_vpn_installations SET engine_epoch=$2 WHERE node_id=$1`, current.NodeID, current.EngineEpoch)
	trusted := Authenticated(p, func(context.Context, pgx.Tx, Owner) error { return nil })
	if e = trusted.AcknowledgePreviousEngine(ctx, current); e != nil {
		t.Fatal(e)
	}
	resumed, e := s.ClaimExplicit(ctx, current, request)
	if e != nil || resumed.State != "pending" || resumed.Generation != l.Generation || resumed.Revision != l.Revision+1 {
		t.Fatal("resume", resumed, e)
	}
	resumed, e = s.Activate(ctx, current, resumed.Ref)
	if e != nil {
		t.Fatal(e)
	}
	if e = trusted.AcknowledgePreviousEngine(ctx, current); e != nil {
		t.Fatal(e)
	}
	again, e := s.Status(ctx, current, resumed.Ref)
	if e != nil || again.State != "active" || again.Revision != resumed.Revision {
		t.Fatal("fence replay", e)
	}
	if _, e = s.ClaimExplicit(ctx, old, request); !errors.Is(e, ErrDenied) {
		t.Fatal("old epoch accepted", e)
	}
	// A manual takeover on another node still wins; another restart cannot reclaim it.
	other := owner(t, p, u)
	next, e := s.ClaimExplicit(ctx, other, id(t))
	if e != nil {
		t.Fatal(e)
	}
	current.EngineEpoch = strings.Repeat("f", 32)
	exec(t, p, `UPDATE nodes_vpn_installations SET engine_epoch=$2 WHERE node_id=$1`, current.NodeID, current.EngineEpoch)
	if e = trusted.AcknowledgePreviousEngine(ctx, current); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Activate(ctx, other, next.Ref); e != nil {
		t.Fatal(e)
	}
	if lost, err := s.ClaimExplicit(ctx, current, request); err != nil || lost.State != "replaced" {
		t.Fatal("stale intent reason lost", err)
	}
}
