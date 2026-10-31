package database_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
)

func TestRandomIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := database.NewID()
		if err != nil || !database.ValidID(id) || seen[id] {
			t.Fatal("invalid or duplicate random ID")
		}
		seen[id] = true
	}
	for _, id := range []string{"", "../../private", "person@example.com", "not-a-uuid"} {
		if database.ValidID(id) {
			t.Fatal("accepted nonopaque ID")
		}
	}
}

func TestPostgresMigrationsConcurrentIdempotentAndDrift(t *testing.T) {
	p := dbtest.NewUnmigrated(t)
	ctx := context.Background()
	if database.Ready(ctx, p) == nil {
		t.Fatal("unmigrated DB considered ready")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs <- database.Migrate(ctx, p) }()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Migrate(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := database.Ready(ctx, p); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil || count < 2 {
		t.Fatal("missing embedded migrations", count, err)
	}
	if _, err := p.Exec(ctx, `UPDATE schema_migrations SET checksum=repeat('0',64) WHERE version=1`); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(database.Migrate(ctx, p), database.ErrSchemaDrift) {
		t.Fatal("checksum drift accepted")
	}
	if !errors.Is(database.Ready(ctx, p), database.ErrSchemaDrift) {
		t.Fatal("readiness accepted checksum drift")
	}
}

func TestPostgresMigrationFailureRollsBackWholeBatch(t *testing.T) {
	p := dbtest.NewUnmigrated(t)
	ctx := context.Background()
	// This owned fixture collision makes 001 fail after schema_migrations creation.
	if _, err := p.Exec(ctx, `CREATE TABLE jobs(sentinel boolean)`); err != nil {
		t.Fatal(err)
	}
	if database.Migrate(ctx, p) == nil {
		t.Fatal("invalid migration unexpectedly succeeded")
	}
	var missing bool
	if err := p.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NULL`).Scan(&missing); err != nil || !missing {
		t.Fatal("partial migration metadata leaked", err)
	}
	if _, err := p.Exec(ctx, `DROP TABLE jobs`); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, p); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresNewerDatabaseIsNotDowngraded(t *testing.T) {
	p := dbtest.New(t)
	ctx := context.Background()
	if _, err := p.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum) VALUES(999,'999_future.sql',repeat('a',64))`); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(database.Migrate(ctx, p), database.ErrSchemaDrift) {
		t.Fatal("newer database accepted by older binary")
	}
}
