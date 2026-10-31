// Package database provides explicit, transactional schema migration and IDs.
package database

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/migrations"
)

var ErrSchemaDrift = errors.New("schema_migration_drift")

type migration struct {
	version             int
	name, checksum, sql string
}

var migrationName = regexp.MustCompile(`^([0-9]{3})_[a-z0-9_]+\.sql$`)

func load() ([]migration, error) {
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return nil, err
	}
	list := []migration{}
	for _, e := range entries {
		match := migrationName.FindStringSubmatch(e.Name())
		if e.IsDir() || match == nil {
			return nil, ErrSchemaDrift
		}
		version, _ := strconv.Atoi(match[1])
		data, err := fs.ReadFile(migrations.Files, e.Name())
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		list = append(list, migration{version, e.Name(), hex.EncodeToString(hash[:]), string(data)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].version < list[j].version })
	for i, m := range list {
		if m.version != i+1 {
			return nil, ErrSchemaDrift
		}
	}
	if len(list) == 0 {
		return nil, ErrSchemaDrift
	}
	return list, nil
}

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func applied(ctx context.Context, q queryer, expected []migration, complete bool) (int, error) {
	rows, err := q.Query(ctx, `SELECT version,name,checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var version int
		var name, checksum string
		if err = rows.Scan(&version, &name, &checksum); err != nil {
			return 0, err
		}
		if count >= len(expected) || version != expected[count].version || name != expected[count].name || checksum != expected[count].checksum {
			return 0, ErrSchemaDrift
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return 0, err
	}
	if complete && count != len(expected) {
		return 0, ErrSchemaDrift
	}
	return count, nil
}

// Migrate runs only when explicitly requested. The transaction-scoped advisory
// lock serializes migrators, including creation of the version table. All pending
// DDL and metadata commit together; drift, gaps and downgrade attempts fail closed.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	list, err := load()
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer Rollback(tx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(72619871310401)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
version integer PRIMARY KEY CHECK(version>0),name text UNIQUE NOT NULL,
checksum text NOT NULL CHECK(checksum ~ '^[0-9a-f]{64}$'),
applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	count, err := applied(ctx, tx, list, false)
	if err != nil {
		return err
	}
	for _, m := range list[count:] {
		if _, err = tx.Exec(ctx, m.sql); err != nil {
			return fmt.Errorf("migration_%03d: %w", m.version, err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)`, m.version, m.name, m.checksum); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Ready is read-only. It never repairs or migrates a database during an HTTP call.
func Ready(ctx context.Context, pool *pgxpool.Pool) error {
	list, err := load()
	if err != nil {
		return err
	}
	_, err = applied(ctx, pool, list, true)
	return err
}

// Rollback allows cancellation of the caller without leaving an idle transaction,
// while a broken database connection cannot block cleanup indefinitely.
func Rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// NewID returns a random RFC 4122 UUID independent of production identities.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return uuidPattern.MatchString(id) }
