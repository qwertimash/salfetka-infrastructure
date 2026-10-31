package subscriptionsets

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"sync"
	"testing"
	"time"
)

func TestInviteEnrollmentRetryIsolationLimitAndRevocation(t *testing.T) {
	s, p, user, actor := fixture(t)
	a := access.New(p, s.Builder.Vault)
	if _, e := p.Exec(ctx, "INSERT INTO access_entitlements(id,user_id,state,expires_at,device_limit,group_id,revision) VALUES($1,$2,'active',clock_timestamp()+interval '1 day',1,$3,1)", id(t), user, access.DefaultGroupID); e != nil {
		t.Fatal(e)
	}
	set := create(t, p, s, actor, "invite-set-create-0001")
	assignment, _, e := assign(p, s, Assign{Actor: actor, Key: "invite-set-assign-0001", UserID: user, SetID: set.ID, State: "active"})
	if e != nil {
		t.Fatal(e)
	}
	mint := func(key string) access.Invitation {
		t.Helper()
		v, _, e := transact(p, func(tx pgx.Tx) (access.Invitation, bool, error) {
			return a.MintInviteTx(ctx, tx, actor, assignment.ID, key)
		})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	invite := mint("invite-create-00000001")
	again := mint("invite-create-00000001")
	if invite != again {
		t.Fatal("retry rotated or extended invite")
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	proof := access.InviteProof{PublicKey: base64.RawURLEncoding.EncodeToString(pub), IssuedAt: time.Now().Unix(), Name: "Test phone"}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(access.InviteMessage(invite.Token, proof))))
	consume := func(token string, proof access.InviteProof) (access.EnrolledDevice, error) {
		v, _, e := transact(p, func(tx pgx.Tx) (access.EnrolledDevice, bool, error) {
			v, e := a.ConsumeInviteTx(ctx, tx, token, proof)
			return v, false, e
		})
		return v, e
	}
	changed := proof
	changed.Name = "Other name"
	if _, e = consume(invite.Token, changed); !errors.Is(e, access.ErrProof) {
		t.Fatal("unsigned name accepted", e)
	}
	var wg sync.WaitGroup
	results := make(chan access.EnrolledDevice, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v, e := consume(invite.Token, proof); results <- v; errs <- e }()
	}
	wg.Wait()
	first, second := <-results, <-results
	if e = <-errs; e != nil {
		t.Fatal(e)
	}
	if e = <-errs; e != nil {
		t.Fatal(e)
	}
	if first != second || first.UserID != user || first.DeviceID == "" {
		t.Fatal("duplicate physical identity")
	}
	otherPub, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	changed = proof
	changed.PublicKey = base64.RawURLEncoding.EncodeToString(otherPub)
	changed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherKey, []byte(access.InviteMessage(invite.Token, changed))))
	if _, e = consume(invite.Token, changed); !errors.Is(e, access.ErrProof) {
		t.Fatal("second device consumed same invite", e)
	}
	fresh := mint("invite-create-00000002")
	changed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherKey, []byte(access.InviteMessage(fresh.Token, changed))))
	if _, e = consume(fresh.Token, changed); !errors.Is(e, access.ErrLimit) {
		t.Fatal("device limit bypass", e)
	}
	if _, e = p.Exec(ctx, "UPDATE access_devices SET state='revoked' WHERE id=$1", first.DeviceID); e != nil {
		t.Fatal(e)
	}
	if _, e = consume(invite.Token, proof); !errors.Is(e, access.ErrProof) {
		t.Fatal("revoked device resurrected", e)
	}
	if _, e = p.Exec(ctx, "UPDATE account_set_assignments SET state='revoked',revision=revision+1 WHERE id=$1", assignment.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = consume(fresh.Token, changed); !errors.Is(e, access.ErrProof) {
		t.Fatal("unassigned invite accepted", e)
	}
	var count int
	p.QueryRow(ctx, "SELECT count(*) FROM access_devices WHERE user_id=$1", user).Scan(&count)
	if count != 1 {
		t.Fatal("unexpected identities", count)
	}
}
