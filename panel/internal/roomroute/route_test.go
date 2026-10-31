package roomroute

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"

	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
)

func TestStableReservationCapacityAndRollback(t *testing.T) {
	p := dbtest.New(t)
	ctx := context.Background()
	id := func() string { s, _ := database.NewID(); return s }
	node, install := id(), id()
	var group string
	if e := p.QueryRow(ctx, "SELECT id::text FROM access_groups ORDER BY id LIMIT 1").Scan(&group); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, "INSERT INTO nodes_registry(id,name) VALUES($1,'Room test')", node); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, "INSERT INTO nodes_vpn_installations(node_id,installation_id,group_id,enabled) VALUES($1,$2,$3,true)", node, install, group); e != nil {
		t.Fatal(e)
	}
	for i := 0; i <= MaxRooms; i++ {
		u := id()
		if _, e := p.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,'Room test')", u); e != nil {
			t.Fatal(e)
		}
		tx, e := p.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		room, e := Reserve(ctx, tx, install, u)
		if i == MaxRooms {
			if e != ErrCapacity {
				t.Fatal("capacity not enforced", e)
			}
			database.Rollback(tx)
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		again, e := Reserve(ctx, tx, install, u)
		if e != nil || again != room {
			t.Fatal("non-idempotent reservation")
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
	}
	tx, _ := p.Begin(ctx)
	defer database.Rollback(tx)
	if _, e := Lookup(ctx, tx, install, id()); e != pgx.ErrNoRows {
		t.Fatal("missing route fabricated", e)
	}
	var count int
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM account_rooms").Scan(&count); e != nil || count != MaxRooms {
		t.Fatal("partial excess reservation", count, e)
	}
}
func TestProviderPathPreserved(t *testing.T) {
	room := strings.Repeat("a", 64)
	for base, want := range map[string]string{"https://example.invalid/old": "https://example.invalid/" + room, "https://example.invalid/base/old": "https://example.invalid/base/" + room} {
		got, e := URL(base, room)
		if e != nil || got != want {
			t.Fatal(fmt.Sprintf("path mismatch %v", e))
		}
	}
}
