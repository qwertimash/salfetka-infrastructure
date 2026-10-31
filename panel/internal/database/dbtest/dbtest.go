// Package dbtest creates an exactly scoped, disposable schema on an explicitly
// supplied local test database. It never creates/drops databases or public tables.
package dbtest

import (
	"context"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
)

var testDatabase = regexp.MustCompile(`^panel_(?:b1_)?test(?:_[a-z0-9_]+)?$`)

func safeHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func New(t testing.TB) *pgxpool.Pool {
	t.Helper()
	p := NewUnmigrated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := database.Migrate(ctx, p); err != nil {
		t.Fatal("test migration failed:", err)
	}
	return p
}

func NewUnmigrated(t testing.TB) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("PANEL_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("integration not run: PANEL_TEST_DATABASE_URL is absent")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	if !safeHost(cfg.ConnConfig.Host) || !testDatabase.MatchString(cfg.ConnConfig.Database) {
		t.Fatal("test DB must be loopback and explicitly named panel_test or panel_b1_test[_suffix]")
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if !safeHost(fallback.Host) {
			t.Fatal("non-loopback test DB fallback forbidden")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, cfg.ConnConfig.Copy())
	if err != nil {
		t.Fatal("test DB connection failed")
	}
	id, err := database.NewID()
	if err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	schema := "b1_test_" + strings.ReplaceAll(id, "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatal("create test schema:", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close(ctx)
		t.Fatal("test pool setup failed")
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Only this invocation's generated UUID schema is ever removed.
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error("test schema cleanup:", err)
		}
		admin.Close(cleanup)
	})
	return pool
}
