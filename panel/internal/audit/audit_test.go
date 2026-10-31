package audit

import (
	"context"
	"errors"
	"testing"

	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
)

func TestSanitizedFieldsOnly(t *testing.T) {
	id, _ := database.NewID()
	if !valid("anonymous", "identity.login_failed", "", "failed") || !valid(id, "job.enqueued", id, "accepted") {
		t.Fatal("valid audit rejected")
	}
	for _, v := range [][4]string{
		{"private@example.com", "identity.login_failed", "", "failed"},
		{"anonymous", "identity.password_secret", "", "failed"},
		{"system", "job.failed", "https://private.invalid/token", "failed"},
		{"system", "job.failed", id, "raw secret error"},
	} {
		if valid(v[0], v[1], v[2], v[3]) {
			t.Fatal("unsafe audit accepted")
		}
	}
}

func TestPostgresAuditRollbackImmutableAndPagination(t *testing.T) {
	p := dbtest.New(t)
	ctx := context.Background()
	s := New(p)
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = Append(ctx, tx, "anonymous", "identity.login_failed", "", "failed"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := s.List(ctx, 100, "")
	if err != nil || len(entries) != 0 {
		t.Fatal("audit survived rollback", err)
	}
	for i := 0; i < 4; i++ {
		tx, err = p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = Append(ctx, tx, "system", "job.failed", "", "failed"); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.List(ctx, 2, "")
	if err != nil || len(first) != 2 {
		t.Fatal(err)
	}
	second, err := s.List(ctx, 2, first[1].ID)
	if err != nil || len(second) != 2 {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range append(first, second...) {
		if seen[e.ID] {
			t.Fatal("duplicate cursor page")
		}
		seen[e.ID] = true
	}
	for _, query := range []string{`UPDATE audit_events SET outcome='succeeded'`, `DELETE FROM audit_events`, `TRUNCATE audit_events`} {
		if _, err = p.Exec(ctx, query); err == nil {
			t.Fatal("audit mutation allowed")
		}
	}
	unknown, _ := database.NewID()
	if _, err = s.List(ctx, 5, unknown); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown cursor accepted")
	}
}
