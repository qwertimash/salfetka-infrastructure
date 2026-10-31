package subscriptionsets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
)

var ctx = context.Background()

func id(t *testing.T) string {
	t.Helper()
	s, e := database.NewID()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func document(title string) builder.Document {
	return builder.Document{Title: title, Recipe: releases.Recipe{MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1}}}
}
func fixture(t *testing.T) (*Store, *pgxpool.Pool, string, string) {
	t.Helper()
	p := dbtest.New(t)
	v, e := secrets.New(bytes.Repeat([]byte{31}, 32))
	if e != nil {
		t.Fatal(e)
	}
	user, actor := id(t), id(t)
	if _, e = p.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,'Synthetic account')", user); e != nil {
		t.Fatal(e)
	}
	return &Store{Builder: builder.New(p, v)}, p, user, actor
}
func transact[T any](p *pgxpool.Pool, f func(pgx.Tx) (T, bool, error)) (T, bool, error) {
	var zero T
	tx, e := p.Begin(ctx)
	if e != nil {
		return zero, false, e
	}
	defer database.Rollback(tx)
	out, replay, e := f(tx)
	if e == nil {
		e = tx.Commit(ctx)
	}
	return out, replay, e
}
func save(p *pgxpool.Pool, s *Store, m Save) (Set, bool, error) {
	return transact(p, func(tx pgx.Tx) (Set, bool, error) { return s.SaveTx(ctx, tx, m) })
}
func assign(p *pgxpool.Pool, s *Store, m Assign) (Assignment, bool, error) {
	return transact(p, func(tx pgx.Tx) (Assignment, bool, error) { return s.AssignTx(ctx, tx, m) })
}
func create(t *testing.T, p *pgxpool.Pool, s *Store, actor, key string) Set {
	t.Helper()
	v, _, e := save(p, s, Save{Actor: actor, Key: key, Document: document("Салфетка VPN")})
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestSetVersionsPinnedEncryptedAndRetry(t *testing.T) {
	s, p, _, actor := fixture(t)
	m := Save{Actor: actor, Key: "set-create-00000001", Document: document("Private title")}
	v, replay, e := save(p, s, m)
	if e != nil || replay || v.Revision != 1 {
		t.Fatal(v, e)
	}
	var draft string
	var cipher []byte
	e = p.QueryRow(ctx, `SELECT s.draft_id::text,b.body_ciphertext FROM subscription_sets s JOIN builder_versions b ON b.draft_id=s.draft_id WHERE s.id=$1`, v.ID).Scan(&draft, &cipher)
	if e != nil || bytes.Contains(cipher, []byte("Private title")) {
		t.Fatal("unencrypted document", e)
	}
	// Existing builder API is still usable: its edit must not alter a set snapshot.
	_, _, e = transact(p, func(tx pgx.Tx) (builder.Draft, bool, error) {
		return s.Builder.SaveTx(ctx, tx, builder.Mutation{Actor: actor, Key: "legacy-builder-edit-0001", ID: draft, Revision: 1, Document: document("Unpublished edit")})
	})
	if e != nil {
		t.Fatal(e)
	}
	tx, _ := p.Begin(ctx)
	first, e := s.ReadTx(ctx, tx, v.ID, 0)
	database.Rollback(tx)
	if e != nil || first.Document.Title != "Private title" {
		t.Fatal("mutable saved set", e)
	}
	changed := m
	changed.ID = v.ID
	changed.Revision = 1
	changed.Key = "set-update-00000001"
	changed.Document = document("New version")
	v2, _, e := save(p, s, changed)
	if e != nil || v2.Revision != 2 {
		t.Fatal(v2, e)
	}
	recovered, replay, e := save(p, s, m)
	if e != nil || !replay || recovered.ID != v.ID || recovered.Revision != 1 || recovered.Document.Title != "Private title" {
		t.Fatal("lost response retry changed", e)
	}
	m.Document = document("Different payload")
	if _, _, e = save(p, s, m); !errors.Is(e, ErrConflict) {
		t.Fatal("key collision", e)
	}
	changed.Key = "stale-save-00000001"
	if _, _, e = save(p, s, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("stale save", e)
	}
	var count int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='subscription_set.save'").Scan(&count); e != nil || count != 2 {
		t.Fatal("duplicate audit", count, e)
	}
}

func TestMultipleSetsAccountIsolationRevocationAndNoCredentials(t *testing.T) {
	s, p, user, actor := fixture(t)
	a := create(t, p, s, actor, "create-set-a-000001")
	b := create(t, p, s, actor, "create-set-b-000001")
	m := Assign{Actor: actor, Key: "assign-set-a-000001", UserID: user, SetID: a.ID, State: "active"}
	one, _, e := assign(p, s, m)
	if e != nil {
		t.Fatal(e)
	}
	m2 := m
	m2.Key = "assign-set-b-000001"
	m2.SetID = b.ID
	two, _, e := assign(p, s, m2)
	if e != nil || two.ID == one.ID {
		t.Fatal(e)
	}
	revoke := m
	revoke.Key = "revoke-set-a-000001"
	revoke.Revision = 1
	revoke.State = "revoked"
	removed, _, e := assign(p, s, revoke)
	if e != nil || removed.Revision != 2 {
		t.Fatal(e)
	}
	recovered, replay, e := assign(p, s, m)
	if e != nil || !replay || recovered.ID != one.ID || recovered.Revision != 1 {
		t.Fatal("lost response replay", e)
	}
	tx, _ := p.Begin(ctx)
	page, e := s.AssignmentsTx(ctx, tx, user, "")
	database.Rollback(tx)
	if e != nil || len(page.Items) != 2 {
		t.Fatal(page, e)
	}
	for _, a := range page.Items {
		if a.ID == one.ID && a.State != "revoked" {
			t.Fatal("replay reactivated revoked assignment")
		}
		if a.ID == two.ID && (a.State != "active" || a.Revision != 1) {
			t.Fatal("unrelated assignment changed")
		}
	}
	stale := m
	stale.Key = "stale-reactivate-00001"
	stale.Revision = 1
	if _, _, e = assign(p, s, stale); !errors.Is(e, ErrConflict) {
		t.Fatal("stale reactivation", e)
	}
	stale.Revision = 2
	back, _, e := assign(p, s, stale)
	if e != nil || back.ID != one.ID || back.Revision != 3 {
		t.Fatal("explicit reassign changed identity", e)
	}
	other := id(t)
	if _, e = p.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,'Another account')", other); e != nil {
		t.Fatal(e)
	}
	tx, _ = p.Begin(ctx)
	empty, e := s.AssignmentsTx(ctx, tx, other, "")
	database.Rollback(tx)
	if e != nil || len(empty.Items) != 0 {
		t.Fatal("account isolation", e)
	}
	for _, table := range []string{"access_devices", "access_credentials", "subscriptions", "access_outbox", "nodes_commands"} {
		var n int
		if e = p.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil || n != 0 {
			t.Fatal("assignment unexpectedly provisioned access", table, n, e)
		}
	}
	if _, e = p.Exec(ctx, "UPDATE access_users SET state='suspended' WHERE id=$1", user); e != nil {
		t.Fatal(e)
	}
	stale.Key = "suspended-assign-0001"
	stale.Revision = 3
	if _, _, e = assign(p, s, stale); !errors.Is(e, ErrConflict) {
		t.Fatal("suspended user assigned", e)
	}
	stale.State = "revoked"
	if _, _, e = assign(p, s, stale); e != nil {
		t.Fatal("cannot revoke suspended user", e)
	}
}

func TestConcurrentSaveAndAssignmentCAS(t *testing.T) {
	s, p, user, actor := fixture(t)
	v := create(t, p, s, actor, "create-concurrent-001")
	for _, operation := range []string{"save", "assign"} {
		var wg sync.WaitGroup
		start := make(chan struct{})
		out := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				key := fmt.Sprintf("concurrent-%s-%04d", operation, i)
				var e error
				if operation == "save" {
					_, _, e = save(p, s, Save{Actor: actor, Key: key, ID: v.ID, Revision: 1, Document: document("Concurrent update")})
				} else {
					_, _, e = assign(p, s, Assign{Actor: actor, Key: key, UserID: user, SetID: v.ID, State: "active"})
				}
				out <- e
			}(i)
		}
		close(start)
		wg.Wait()
		close(out)
		success, conflicts := 0, 0
		for e := range out {
			if e == nil {
				success++
			} else if errors.Is(e, ErrConflict) {
				conflicts++
			} else {
				t.Fatal(e)
			}
		}
		if success != 1 || conflicts != 1 {
			t.Fatal(operation, success, conflicts)
		}
	}
}

func TestConcurrentIdenticalRequestHasOneEffect(t *testing.T) {
	s, p, user, actor := fixture(t)
	m := Save{Actor: actor, Key: "identical-create-0001", Document: document("Shared set")}
	var wg sync.WaitGroup
	ids := make(chan string, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v, _, e := save(p, s, m); ids <- v.ID; errs <- e }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	first, second := <-ids, <-ids
	if first != second {
		t.Fatal("duplicate set from retry")
	}
	assignment := Assign{Actor: actor, Key: "identical-assign-0001", UserID: user, SetID: first, State: "active"}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _, e := assign(p, s, assignment)
			if e != nil {
				t.Error(e)
			}
			ids <- a.ID
		}()
	}
	wg.Wait()
	if <-ids != <-ids {
		t.Fatal("duplicate assignment from retry")
	}
	// One key cannot be repurposed across operation types.
	assignment.Key = m.Key
	if _, _, e := assign(p, s, assignment); !errors.Is(e, ErrConflict) {
		t.Fatal("cross-operation replay collision", e)
	}
	bad := m
	bad.Key = "shared-credential-001"
	bad.Document.Recipe.ExternalCredentials = true
	if _, _, e := save(p, s, bad); !errors.Is(e, ErrInvalid) {
		t.Fatal("shared imported credentials accepted", e)
	}
}

func TestSetVersionForeignKeysRejectCrossSetAndMissingDraft(t *testing.T) {
	s, p, _, actor := fixture(t)
	a := create(t, p, s, actor, "fk-create-set-a-001")
	b := create(t, p, s, actor, "fk-create-set-b-001")
	var da, db string
	if e := p.QueryRow(ctx, "SELECT draft_id::text FROM subscription_sets WHERE id=$1", a.ID).Scan(&da); e != nil {
		t.Fatal(e)
	}
	if e := p.QueryRow(ctx, "SELECT draft_id::text FROM subscription_sets WHERE id=$1", b.ID).Scan(&db); e != nil {
		t.Fatal(e)
	}
	for _, pair := range []struct {
		draft    string
		revision int64
	}{{db, 1}, {da, 999}} {
		if _, e := p.Exec(ctx, "INSERT INTO subscription_set_versions(set_id,revision,draft_id,draft_revision) VALUES($1,2,$2,$3)", a.ID, pair.draft, pair.revision); e == nil {
			t.Fatal("invalid version reference")
		}
	}
}

func TestConstraintsRollbackAndBoundedLists(t *testing.T) {
	s, p, user, actor := fixture(t)
	for i := 0; i < 52; i++ {
		v := create(t, p, s, actor, fmt.Sprintf("pagination-create-%04d", i))
		if _, _, e := assign(p, s, Assign{Actor: actor, Key: fmt.Sprintf("pagination-assign-%04d", i), UserID: user, SetID: v.ID, State: "active"}); e != nil {
			t.Fatal(e)
		}
	}
	tx, _ := p.Begin(ctx)
	page, e := s.ListTx(ctx, tx, "")
	if e != nil || len(page.Items) != 50 || page.NextCursor == "" {
		t.Fatal("first set page", e)
	}
	next, e := s.ListTx(ctx, tx, page.NextCursor)
	if e != nil || len(next.Items) != 2 || next.NextCursor != "" {
		t.Fatal("last set page", e)
	}
	assignments, e := s.AssignmentsTx(ctx, tx, user, "")
	if e != nil || len(assignments.Items) != 50 {
		t.Fatal(e)
	}
	last, e := s.AssignmentsTx(ctx, tx, user, assignments.NextCursor)
	if e != nil || len(last.Items) != 2 || last.NextCursor != "" {
		t.Fatal(e)
	}
	database.Rollback(tx)
	for _, q := range []string{
		"UPDATE subscription_set_versions SET revision=revision",
		"DELETE FROM subscription_set_mutations",
		"TRUNCATE subscription_set_versions CASCADE",
		"UPDATE subscription_sets SET revision=999",
		"UPDATE subscription_set_versions SET draft_id='00000000-0000-4000-8000-000000000099'",
	} {
		tx, _ = p.Begin(ctx)
		_, e = tx.Exec(ctx, q)
		if e == nil {
			e = tx.Commit(ctx)
		}
		database.Rollback(tx)
		if e == nil {
			t.Fatal("constraint bypass", q)
		}
	}
	tx, _ = p.Begin(ctx)
	_, _, e = s.SaveTx(ctx, tx, Save{Actor: actor, Key: "rollback-create-00001", Document: document("Rolled back")})
	if e != nil {
		t.Fatal(e)
	}
	database.Rollback(tx)
	var n int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM subscription_sets").Scan(&n); e != nil || n != 52 {
		t.Fatal("partial save leaked", n, e)
	}
	if _, _, e = assign(p, s, Assign{Actor: actor, Key: "unknown-set-0000001", UserID: user, SetID: id(t), State: "active"}); !errors.Is(e, ErrNotFound) {
		t.Fatal("unknown set", e)
	}
	if _, _, e = save(p, s, Save{Actor: actor, Key: "invalid-save-000001", Document: document("")}); !errors.Is(e, builder.ErrInvalid) {
		t.Fatal("invalid builder document", e)
	}
}
