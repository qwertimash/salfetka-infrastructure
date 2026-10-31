package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
	"salfetka/panel/internal/subscriptionsets"
)

func TestRuntimeSubscriptionSetsWriteAndHistoryBoundary(t *testing.T) {
	pool, role, schema := runtimeFixture(t)
	ctx := context.Background()
	v, _ := secrets.New(bytes.Repeat([]byte{18}, 32))
	store := subscriptionsets.Store{Builder: builder.New(pool, v)}
	actor, _ := database.NewID()
	user, _ := database.NewID()
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer database.Rollback(tx)
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,'Runtime fixture')", user); e != nil {
		t.Fatal(e)
	}
	doc := builder.Document{Title: "Runtime set", Recipe: releases.Recipe{MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1}}}
	s, _, e := store.SaveTx(ctx, tx, subscriptionsets.Save{Actor: actor, Key: "runtime-create-set-001", Document: doc})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = store.SaveTx(ctx, tx, subscriptionsets.Save{Actor: actor, Key: "runtime-update-set-001", ID: s.ID, Revision: 1, Document: doc}); e != nil {
		t.Fatal(e)
	}
	a, _, e := store.AssignTx(ctx, tx, subscriptionsets.Assign{Actor: actor, Key: "runtime-assign-set-001", UserID: user, SetID: s.ID, State: "active"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = store.AssignTx(ctx, tx, subscriptionsets.Assign{Actor: actor, Key: "runtime-revoke-set-001", UserID: user, SetID: s.ID, State: "revoked", Revision: a.Revision}); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"subscription_sets", "subscription_set_versions", "account_set_assignments", "subscription_set_mutations"} {
		var destructive bool
		if e = tx.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'DELETE,TRUNCATE')", pgx.Identifier{schema, table}.Sanitize()).Scan(&destructive); e != nil || destructive {
			t.Fatal("destructive set privileges", table, e)
		}
	}
	for _, table := range []string{"subscription_set_versions", "subscription_set_mutations"} {
		var mutable bool
		if e = tx.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'UPDATE')", pgx.Identifier{schema, table}.Sanitize()).Scan(&mutable); e != nil || mutable {
			t.Fatal("mutable set history", table, e)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
}

func runtimeFixture(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	pool := dbtest.New(t)
	ctx := context.Background()
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	id, err := database.NewID()
	if err != nil {
		t.Fatal(err)
	}
	role := "b1_runtime_" + strings.ReplaceAll(id, "-", "")
	// Only this test's generated role is ever modified, never panel_runtime.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil {
			t.Error("role cleanup lookup failed", err)
			return
		}
		if exists {
			quoted := pgx.Identifier{role}.Sanitize()
			if _, err := pool.Exec(ctx, "DROP OWNED BY "+quoted); err != nil {
				t.Error("test role grants cleanup failed", err)
			}
			if _, err := pool.Exec(ctx, "DROP ROLE "+quoted); err != nil {
				t.Error("test role cleanup failed", err)
			}
		}
	})
	if err := provisionRuntimeTarget(ctx, pool, strings.Repeat("A", 43), role, schema); err != nil {
		t.Fatal("fresh synthetic runtime role failed", err)
	}
	return pool, role, schema
}

func passwordVerifier(t *testing.T, pool *pgxpool.Pool, role string) string {
	t.Helper()
	var verifier string
	if err := pool.QueryRow(context.Background(), "SELECT rolpassword FROM pg_authid WHERE rolname=$1", role).Scan(&verifier); err != nil {
		t.Fatal("cannot inspect synthetic role verifier")
	}
	return verifier
}

// Exercise the installed role, not the migrator used by most store fixtures.
// A fresh pilot previously migrated these tables but could not fence a Jitsi
// epoch or allocate a personal room because provisioning omitted their ACLs.
func TestRuntimeCanReadAndLockBypassState(t *testing.T) {
	pool, role, schema := runtimeFixture(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Rollback(tx)
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"bypass_accounts", "bypass_leases", "account_rooms"} {
		query := "SELECT * FROM " + pgx.Identifier{schema, table}.Sanitize() + " LIMIT 0"
		if table != "account_rooms" {
			query += " FOR UPDATE"
		}
		rows, e := tx.Query(ctx, query)
		if e != nil {
			t.Fatalf("runtime cannot read/lock %s: %v", table, e)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		var insert, destructive bool
		e = tx.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'INSERT'), has_table_privilege(current_user,$1,'DELETE,TRUNCATE')", pgx.Identifier{schema, table}.Sanitize()).Scan(&insert, &destructive)
		if e != nil || !insert || destructive {
			t.Fatalf("unsafe or missing bypass privileges for %s", table)
		}
	}
	var mutableRooms bool
	if e := tx.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'UPDATE')", pgx.Identifier{schema, "account_rooms"}.Sanitize()).Scan(&mutableRooms); e != nil || mutableRooms {
		t.Fatal("room assignments must remain immutable")
	}
}

func TestRuntimeProvisionRepeatRotationAndUnsafeRollback(t *testing.T) {
	pool, role, schema := runtimeFixture(t)
	ctx := context.Background()
	if err := provisionRuntimeTarget(ctx, pool, strings.Repeat("A", 43), role, schema); err != nil {
		t.Fatal("legitimate repeat rejected", err)
	}
	beforeRotation := passwordVerifier(t, pool, role)
	if err := provisionRuntimeTarget(ctx, pool, strings.Repeat("B", 43), role, schema); err != nil {
		t.Fatal("password rotation rejected", err)
	}
	// The password verifier changes on rotation; do not emit it into test output.
	rotated := passwordVerifier(t, pool, role)
	if rotated == beforeRotation {
		t.Fatal("rotation did not update the password verifier")
	}
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err := pool.Exec(ctx, "ALTER ROLE "+quoted+" CREATEDB"); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, "ALTER ROLE "+quoted+" NOCREATEDB")
	if err := provisionRuntimeTarget(ctx, pool, strings.Repeat("C", 43), role, schema); !errors.Is(err, errUnsafeRuntimeRole) {
		t.Fatal("unsafe existing role must be rejected", err)
	}
	if passwordVerifier(t, pool, role) != rotated {
		t.Fatal("rejected provisioning changed the password")
	}
	var createdb bool
	if err := pool.QueryRow(ctx, "SELECT rolcreatedb FROM pg_roles WHERE rolname=$1", role).Scan(&createdb); err != nil || !createdb {
		t.Fatal("rejected provisioning silently changed existing privileges")
	}
}

func TestRuntimeRolePrivilegeBoundary(t *testing.T) {
	pool, role, schema := runtimeFixture(t)
	ctx := context.Background()
	quoted := pgx.Identifier{role}.Sanitize()
	qualified := func(table string) string { return pgx.Identifier{schema, table}.Sanitize() }
	var db string
	if err := pool.QueryRow(ctx, "SELECT current_database()").Scan(&db); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		sql  string
	}{
		{"superuser", "ALTER ROLE " + quoted + " SUPERUSER"},
		{"createdb", "ALTER ROLE " + quoted + " CREATEDB"},
		{"createrole", "ALTER ROLE " + quoted + " CREATEROLE"},
		{"replication", "ALTER ROLE " + quoted + " REPLICATION"},
		{"bypassrls", "ALTER ROLE " + quoted + " BYPASSRLS"},
		{"membership_set_role_without_inherit", "GRANT pg_read_all_data TO " + quoted + " WITH INHERIT FALSE, SET TRUE"},
		{"owned_relation", "ALTER TABLE " + qualified("jobs") + " OWNER TO " + quoted},
		{"schema_create", "GRANT CREATE ON SCHEMA " + pgx.Identifier{schema}.Sanitize() + " TO " + quoted},
		{"database_create", "GRANT CREATE ON DATABASE " + pgx.Identifier{db}.Sanitize() + " TO " + quoted},
		{"role_setting", "ALTER ROLE " + quoted + " SET search_path TO public"},
		{"checksum_update", "GRANT UPDATE ON " + qualified("schema_migrations") + " TO " + quoted},
		{"checksum_column_update", "GRANT UPDATE(checksum) ON " + qualified("schema_migrations") + " TO " + quoted},
		{"audit_update", "GRANT UPDATE ON " + qualified("audit_events") + " TO " + quoted},
		{"audit_delete", "GRANT DELETE ON " + qualified("audit_events") + " TO " + quoted},
		{"audit_truncate", "GRANT TRUNCATE ON " + qualified("audit_events") + " TO " + quoted},
		{"audit_column_update", "GRANT UPDATE(outcome) ON " + qualified("audit_events") + " TO " + quoted},
		{"key_check_update", "GRANT UPDATE ON " + qualified("access_key_state") + " TO " + quoted},
		{"key_check_delete", "GRANT DELETE ON " + qualified("access_key_state") + " TO " + quoted},
		{"idempotency_update", "GRANT UPDATE ON " + qualified("access_mutations") + " TO " + quoted},
		{"outbox_delete", "GRANT DELETE ON " + qualified("access_outbox") + " TO " + quoted},
		{"group_update", "GRANT UPDATE ON " + qualified("access_groups") + " TO " + quoted},
		{"table_trigger", "GRANT TRIGGER ON " + qualified("jobs") + " TO " + quoted},
		{"table_maintain", "GRANT MAINTAIN ON " + qualified("jobs") + " TO " + quoted},
		{"table_references", "GRANT REFERENCES ON " + qualified("jobs") + " TO " + quoted},
		{"grant_option", "GRANT SELECT ON " + qualified("jobs") + " TO " + quoted + " WITH GRANT OPTION"},
		{"column_grant_option", "GRANT SELECT(id) ON " + qualified("jobs") + " TO " + quoted + " WITH GRANT OPTION"},
		{"public_audit_update", "GRANT UPDATE ON " + qualified("audit_events") + " TO PUBLIC"},
		{"unrelated_table", "CREATE TABLE " + qualified("unrelated") + "(id int); GRANT SELECT ON " + qualified("unrelated") + " TO " + quoted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Rollback(tx)
			if _, err = tx.Exec(ctx, tc.sql); err != nil {
				t.Fatal("fixture mutation failed", err)
			}
			if err = validateRuntimeRole(ctx, tx, role, schema); !errors.Is(err, errUnsafeRuntimeRole) {
				t.Fatal("unsafe role accepted", err)
			}
		})
	}
	if err := provisionRuntimeTarget(ctx, pool, strings.Repeat("D", 43), role, schema); err != nil {
		t.Fatal("rolled back fixture changes leaked into legitimate retry", err)
	}
}
