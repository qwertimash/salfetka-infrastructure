package bypasslease

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
)

func id(t *testing.T) string {
	t.Helper()
	s, e := database.NewID()
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestExpiredRefusalPreservesClockWatermark(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	o := owner(t, p, u)
	l := active(t, s, o)
	exec(t, p, `UPDATE bypass_leases SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, u)
	var before, after time.Time
	if e := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Renew(ctx, o, l.Ref, 1); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	if e := p.QueryRow(ctx, `SELECT clock_watermark FROM bypass_accounts WHERE user_id=$1`, u).Scan(&after); e != nil || after.Before(before) {
		t.Fatal("refusal rolled back clock evidence", e)
	}
}

func TestPendingExpiryAndGenerationExhaustion(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	o := owner(t, p, u)
	l, e := s.ClaimExplicit(ctx, o, id(t))
	if e != nil {
		t.Fatal(e)
	}
	exec(t, p, `UPDATE bypass_leases SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, u)
	if _, e = s.Activate(ctx, o, l.Ref); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	exec(t, p, `UPDATE bypass_accounts SET generation=$2 WHERE user_id=$1`, u, MaxSequence)
	if _, e = s.ClaimExplicit(ctx, o, id(t)); !errors.Is(e, ErrConflict) {
		t.Fatal("generation wrapped", e)
	}
	l, e = s.Status(ctx, o, l.Ref)
	if e != nil || l.State != "pending" {
		t.Fatal("partial exhausted claim", l, e)
	}
}
func exec(t *testing.T, p *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	if _, e := p.Exec(context.Background(), q, args...); e != nil {
		t.Fatal(e)
	}
}
func account(t *testing.T, p *pgxpool.Pool) string {
	u := id(t)
	exec(t, p, `INSERT INTO access_users(id,name) VALUES($1,'Lease fixture')`, u)
	exec(t, p, `INSERT INTO access_entitlements(id,user_id,state,expires_at,device_limit,group_id,revision) VALUES($1,$2,'active',clock_timestamp()+interval '1 hour',10,$3,1)`, id(t), u, access.DefaultGroupID)
	return u
}
func owner(t *testing.T, p *pgxpool.Pool, u string) Owner {
	o := Owner{NodeID: id(t), InstallationID: id(t), CredentialID: id(t)}
	o.EngineEpoch = strings.ReplaceAll(id(t), "-", "")
	pub := make([]byte, 32)
	if _, e := rand.Read(pub); e != nil {
		t.Fatal(e)
	}
	exec(t, p, `INSERT INTO nodes_registry(id,name,state,serial,public_key,certificate_expires_at) VALUES($1,'Lease node','active',$3,$2,clock_timestamp()+interval '1 hour')`, o.NodeID, pub, o.NodeID)
	exec(t, p, `INSERT INTO nodes_vpn_installations(node_id,installation_id,group_id,enabled,engine_epoch,endpoint) VALUES($1,$2,$3,true,$4,'{"backend":"olcrtc"}')`, o.NodeID, o.InstallationID, access.DefaultGroupID, o.EngineEpoch)
	dev := id(t)
	exec(t, p, `INSERT INTO access_devices(id,user_id,name,state,public_key) VALUES($1,$2,'Lease device','registered',$3)`, dev, u, pub)
	exec(t, p, `INSERT INTO access_credentials(id,user_id,device_id,version,state,ciphertext) VALUES($1,$2,$3,1,'active',$4)`, o.CredentialID, u, dev, make([]byte, 33))
	return o
}
func active(t *testing.T, s *Store, o Owner) Lease {
	t.Helper()
	l, e := s.ClaimExplicit(context.Background(), o, id(t))
	if e != nil {
		t.Fatal(e)
	}
	l, e = s.Activate(context.Background(), o, l.Ref)
	if e != nil {
		t.Fatal(e)
	}
	return l
}

func TestDurableReplaceRequiresCloseNotTimeout(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	a, b := owner(t, p, u), owner(t, p, u)
	other := owner(t, p, account(t, p))
	y := active(t, s, other)
	x := active(t, s, a)
	req := id(t)
	next, e := s.ClaimExplicit(ctx, b, req)
	if e != nil {
		t.Fatal(e)
	}
	if next.Generation != x.Generation+1 || next.State != "pending" {
		t.Fatal(next)
	}
	prior, e := s.Status(ctx, a, x.Ref)
	if e != nil || prior.Reason != Replaced || prior.State != "draining" {
		t.Fatal(prior, e)
	}
	if _, e = s.Activate(ctx, b, next.Ref); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if _, e = s.Renew(ctx, a, x.Ref, x.Revision); !errors.Is(e, ErrStale) {
		t.Fatal(e)
	}
	// Even an expired central timestamp cannot prove old network flows closed.
	exec(t, p, `UPDATE bypass_leases SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1 AND generation=$2`, x.UserID, x.Generation)
	s = &Store{Pool: p} // coordinator process state is disposable, authority is durable
	if _, e = s.Activate(ctx, b, next.Ref); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if _, e = s.AcknowledgeClosed(ctx, b, x.Ref); !errors.Is(e, ErrDenied) {
		t.Fatal("foreign ACK", e)
	}
	for i := 0; i < 2; i++ {
		closed, e := s.AcknowledgeClosed(ctx, a, x.Ref)
		if e != nil || closed.State != "replaced" || closed.Reason != Replaced {
			t.Fatal(closed, e)
		}
	}
	newActive, e := s.Activate(ctx, b, next.Ref)
	if e != nil || newActive.State != "active" {
		t.Fatal(newActive, e)
	}
	duplicate, e := s.Activate(ctx, b, next.Ref)
	if e != nil || !duplicate.ExpiresAt.Equal(newActive.ExpiresAt) {
		t.Fatal("activate retry extended", e)
	}
	retry, e := s.ClaimExplicit(ctx, b, req)
	if e != nil || retry.Ref != newActive.Ref || retry.State != "active" {
		t.Fatal(retry, e)
	}
	oldRetry, e := s.ClaimExplicit(ctx, a, x.RequestID)
	if e != nil || oldRetry.State != "replaced" {
		t.Fatal("old intent resurrected", oldRetry, e)
	}
	still, e := s.Status(ctx, other, y.Ref)
	if e != nil || still.State != "active" || !still.ExpiresAt.Equal(y.ExpiresAt) {
		t.Fatal("other account changed", e)
	}
}

func TestConcurrentClaimsAndRenewReplay(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	a, b := owner(t, p, u), owner(t, p, u)
	req := id(t)
	var wg sync.WaitGroup
	results := make(chan Lease, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, e := s.ClaimExplicit(ctx, a, req)
			if e != nil {
				t.Error(e)
				return
			}
			results <- l
		}()
	}
	wg.Wait()
	close(results)
	var first Lease
	for l := range results {
		if first.Generation == 0 {
			first = l
		}
		if l.Ref != first.Ref {
			t.Error("duplicate claim issued a new generation")
		}
	}
	if _, e := s.ClaimExplicit(ctx, b, req); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	cur, e := s.Activate(ctx, a, first.Ref)
	if e != nil {
		t.Fatal(e)
	}
	renews := make(chan Lease, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, e := s.Renew(ctx, a, cur.Ref, cur.Revision)
			if e != nil {
				t.Error(e)
				return
			}
			renews <- l
		}()
	}
	wg.Wait()
	close(renews)
	var renewed Lease
	for l := range renews {
		if renewed.Revision == 0 {
			renewed = l
		}
		if l.Revision != 2 || !l.ExpiresAt.Equal(renewed.ExpiresAt) {
			t.Error("retry extended twice")
		}
	}
	claims := make(chan Lease, 16)
	for i := 0; i < 16; i++ {
		req := id(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, e := s.ClaimExplicit(ctx, b, req)
			if e != nil {
				t.Error(e)
				return
			}
			claims <- l
		}()
	}
	wg.Wait()
	close(claims)
	var latest Lease
	for l := range claims {
		if l.Generation > latest.Generation {
			latest = l
		}
	}
	var pending, blockers int
	e = p.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='pending'),count(*) FILTER(WHERE state IN('active','draining')) FROM bypass_leases WHERE user_id=$1`, u).Scan(&pending, &blockers)
	if e != nil || pending != 1 || blockers != 1 {
		t.Fatal(pending, blockers, e)
	}
	if _, e = s.AcknowledgeClosed(ctx, a, cur.Ref); e != nil {
		t.Fatal(e)
	}
	activated := 0
	for gen := cur.Generation + 1; gen <= latest.Generation; gen++ {
		_, e := s.Activate(ctx, b, Ref{u, gen})
		if e == nil {
			activated++
		} else if !errors.Is(e, ErrStale) {
			t.Fatal(e)
		}
	}
	if activated != 1 {
		t.Fatal("not exactly one winner", activated)
	}
}

func TestAccessBindingClockAndExpiry(t *testing.T) {
	for _, scenario := range []string{"user_suspended", "credential_revoked", "device_revoked", "group_disabled", "wrong_group", "node_revoked", "wrong_epoch", "expired", "clock", "ordinary_vpn"} {
		t.Run(scenario, func(t *testing.T) {
			p := dbtest.New(t)
			s := &Store{Pool: p}
			ctx := context.Background()
			u := account(t, p)
			o := owner(t, p, u)
			l := active(t, s, o)
			want := ErrDenied
			switch scenario {
			case "user_suspended":
				exec(t, p, `UPDATE access_users SET state='suspended' WHERE id=$1`, u)
			case "credential_revoked":
				exec(t, p, `UPDATE access_credentials SET state='revoked' WHERE id=$1`, o.CredentialID)
			case "device_revoked":
				exec(t, p, `UPDATE access_devices SET state='revoked' WHERE id=$1`, l.DeviceID)
			case "group_disabled":
				exec(t, p, `UPDATE access_groups SET enabled=false WHERE id=$1`, access.DefaultGroupID)
			case "wrong_group":
				group := id(t)
				exec(t, p, `INSERT INTO access_groups(id,name) VALUES($1,'Other')`, group)
				exec(t, p, `UPDATE nodes_vpn_installations SET group_id=$2 WHERE node_id=$1`, o.NodeID, group)
			case "node_revoked":
				exec(t, p, `UPDATE nodes_registry SET state='revoked' WHERE id=$1`, o.NodeID)
			case "wrong_epoch":
				o.EngineEpoch = strings.Repeat("f", 32)
			case "expired":
				exec(t, p, `UPDATE bypass_leases SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, u)
				want = ErrExpired
			case "clock":
				exec(t, p, `UPDATE bypass_accounts SET clock_watermark=clock_timestamp()+interval '1 hour' WHERE user_id=$1`, u)
				want = ErrClock
			case "ordinary_vpn":
				exec(t, p, `UPDATE nodes_vpn_installations SET endpoint='{}' WHERE node_id=$1`, o.NodeID)
			}
			s = &Store{Pool: p}
			if _, e := s.Renew(ctx, o, l.Ref, l.Revision); !errors.Is(e, want) {
				t.Fatal("renew", e, want)
			}
			if scenario == "clock" || scenario == "credential_revoked" || scenario == "expired" {
				if _, e := s.AcknowledgeClosed(ctx, o, l.Ref); e != nil {
					t.Fatal("closure must remain possible", e)
				}
			}
		})
	}
}

func TestDatabaseBlockerConstraintAndNoPartialClaim(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	a, b := owner(t, p, u), owner(t, p, u)
	x := active(t, s, a)
	y, e := s.ClaimExplicit(ctx, b, id(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `UPDATE bypass_leases SET state='active' WHERE user_id=$1 AND generation=$2`, u, y.Generation); e == nil {
		t.Fatal("DB allowed two blockers")
	}
	exec(t, p, `UPDATE bypass_accounts SET clock_watermark=clock_timestamp()+interval '1 hour' WHERE user_id=$1`, u)
	if _, e = s.ClaimExplicit(ctx, b, id(t)); !errors.Is(e, ErrClock) {
		t.Fatal(e)
	}
	var gen int64
	if e = p.QueryRow(ctx, `SELECT generation FROM bypass_accounts WHERE user_id=$1`, u).Scan(&gen); e != nil || gen != y.Generation {
		t.Fatal("partial claim", gen, e)
	}
	if _, e = s.AcknowledgeClosed(ctx, a, x.Ref); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Activate(ctx, b, y.Ref); !errors.Is(e, ErrClock) {
		t.Fatal(e)
	}
	// No operation resets the persistent clock watermark to force availability.
}
