// Package builder owns reusable encrypted drafts, not live assignments.
package builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
)

var ErrInvalid = errors.New("builder_invalid")
var ErrConflict = errors.New("builder_conflict")
var ErrNotFound = errors.New("builder_not_found")
var ErrCapacity = errors.New("builder_capacity")

type Document struct {
	Title  string          `json:"title"`
	Recipe releases.Recipe `json:"recipe"`
}
type Draft struct {
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	Document  Document  `json:"document"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Summary struct {
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	Title     string    `json:"title"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Page struct {
	Items      []Summary `json:"items"`
	NextCursor string    `json:"next_cursor"`
}
type Mutation struct {
	Actor    string   `json:"-"`
	Key      string   `json:"-"`
	ID       string   `json:"id"`
	Revision int64    `json:"revision"`
	Document Document `json:"document"`
}
type Store struct {
	Pool  *pgxpool.Pool
	Vault *secrets.Vault
}

func New(p *pgxpool.Pool, v *secrets.Vault) *Store { return &Store{p, v} }

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

func valid(doc Document) bool {
	r := doc.Recipe
	b, _ := json.Marshal(doc)
	if len(b) > 60000 || !utf8.ValidString(doc.Title) || utf8.RuneCountInString(doc.Title) < 2 || utf8.RuneCountInString(doc.Title) > 80 || strings.TrimSpace(doc.Title) != doc.Title || strings.ContainsAny(doc.Title, "\r\n\x00") || r.Blueprint == nil || r.Blueprint.Version != 1 || len(r.Blueprint.Locations) > 64 || len(r.Blueprint.Routing) > 2 || len(r.Sources) > 16 || len(r.NodeIDs) > 32 || len(r.NodeBindings) > 0 || r.SourceID != "" || r.VersionID != "" || len(r.Network) > 0 || len(r.Locations) > 0 || r.MaxVersion < 1 || r.MaxVersion > 2 || len(r.Engines) == 0 || len(r.Engines) > 3 {
		return false
	}
	for _, l := range r.Blueprint.Locations {
		if len(l.Members) > 32 {
			return false
		}
	}
	return true
}
func aad(id string, revision int64) string { return fmt.Sprintf("builder:%s:%d", id, revision) }
func (s *Store) ReadTx(ctx context.Context, tx pgx.Tx, id string, revision int64) (Draft, error) {
	if !database.ValidID(id) || revision < 0 || s.Vault == nil {
		return Draft{}, ErrInvalid
	}
	var d Draft
	var cipher []byte
	q := `SELECT d.id::text,v.revision,v.body_ciphertext,v.created_at FROM builder_drafts d JOIN builder_versions v ON v.draft_id=d.id AND v.revision=CASE WHEN $2::bigint=0 THEN d.revision ELSE $2 END WHERE d.id=$1`
	e := tx.QueryRow(ctx, q, id, revision).Scan(&d.ID, &d.Revision, &cipher, &d.UpdatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if e != nil {
		return d, e
	}
	b, e := s.Vault.OpenSource(cipher, aad(id, d.Revision))
	if e != nil {
		return d, e
	}
	defer clear(b)
	if json.Unmarshal(b, &d.Document) != nil {
		return d, ErrInvalid
	}
	return d, nil
}
func (s *Store) ListTx(ctx context.Context, tx pgx.Tx, after string) (Page, error) {
	out := Page{Items: []Summary{}}
	if after != "" && !database.ValidID(after) {
		return out, ErrInvalid
	}
	rows, e := tx.Query(ctx, `SELECT id::text,revision,updated_at FROM builder_drafts WHERE ($1='' OR id::text>$1) ORDER BY id LIMIT 51`, after)
	if e != nil {
		return out, e
	}
	type row struct {
		id  string
		rev int64
		at  time.Time
	}
	items := []row{}
	for rows.Next() {
		var r row
		if e = rows.Scan(&r.id, &r.rev, &r.at); e != nil {
			rows.Close()
			return out, e
		}
		items = append(items, r)
	}
	rows.Close()
	if rows.Err() != nil {
		return out, rows.Err()
	}
	if len(items) > 50 {
		items = items[:50]
		out.NextCursor = items[49].id
	}
	for _, r := range items {
		d, e := s.ReadTx(ctx, tx, r.id, r.rev)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, Summary{r.id, r.rev, d.Document.Title, r.at})
	}
	return out, nil
}
func (s *Store) SaveTx(ctx context.Context, tx pgx.Tx, m Mutation) (Draft, bool, error) {
	if !database.ValidID(m.Actor) || !keyPattern.MatchString(m.Key) || !valid(m.Document) || s.Vault == nil || m.Revision < 0 || m.ID != "" && !database.ValidID(m.ID) {
		return Draft{}, false, ErrInvalid
	}
	b, _ := json.Marshal(m)
	hash := sha256.Sum256(b)
	clear(b)
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,71))", m.Actor+":"+m.Key); e != nil {
		return Draft{}, false, e
	}
	var old []byte
	var id string
	var revision int64
	e := tx.QueryRow(ctx, "SELECT request_hash,draft_id::text,revision FROM builder_mutations WHERE actor_id=$1 AND idempotency_key=$2", m.Actor, m.Key).Scan(&old, &id, &revision)
	if e == nil {
		if !bytes.Equal(old, hash[:]) {
			return Draft{}, false, ErrConflict
		}
		d, e := s.ReadTx(ctx, tx, id, revision)
		return d, true, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return Draft{}, false, e
	}
	id = m.ID
	if id == "" {
		if m.Revision != 0 {
			return Draft{}, false, ErrConflict
		}
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(72619871310701)"); e != nil {
			return Draft{}, false, e
		}
		var count int
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM builder_drafts").Scan(&count); e != nil {
			return Draft{}, false, e
		}
		if count >= 500 {
			return Draft{}, false, ErrCapacity
		}
		id, e = database.NewID()
		if e != nil {
			return Draft{}, false, e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO builder_drafts(id,revision) VALUES($1,1)", id); e != nil {
			return Draft{}, false, e
		}
		revision = 1
	} else {
		if e = tx.QueryRow(ctx, "SELECT revision FROM builder_drafts WHERE id=$1 FOR UPDATE", id).Scan(&revision); errors.Is(e, pgx.ErrNoRows) {
			return Draft{}, false, ErrNotFound
		} else if e != nil {
			return Draft{}, false, e
		}
		if revision != m.Revision {
			return Draft{}, false, ErrConflict
		}
		if revision >= 1000 {
			return Draft{}, false, ErrCapacity
		}
		revision++
		if _, e = tx.Exec(ctx, "UPDATE builder_drafts SET revision=$2,updated_at=clock_timestamp() WHERE id=$1", id, revision); e != nil {
			return Draft{}, false, e
		}
	}
	body, _ := json.Marshal(m.Document)
	cipher, e := s.Vault.SealSource(body, aad(id, revision))
	clear(body)
	if e != nil {
		return Draft{}, false, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO builder_versions(draft_id,revision,body_ciphertext) VALUES($1,$2,$3)", id, revision, cipher); e != nil {
		return Draft{}, false, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO builder_mutations(actor_id,idempotency_key,request_hash,draft_id,revision) VALUES($1,$2,$3,$4,$5)", m.Actor, m.Key, hash[:], id, revision); e != nil {
		return Draft{}, false, e
	}
	if e = audit.Append(ctx, tx, m.Actor, "builder.save", id, "succeeded"); e != nil {
		return Draft{}, false, e
	}
	d, e := s.ReadTx(ctx, tx, id, revision)
	return d, false, e
}

// Stage pins an exact saved document. Idempotent replay remains recoverable even
// after later draft edits; a new request against an old draft revision is denied.
func (s *Store) StageTx(ctx context.Context, tx pgx.Tx, releasesStore *releases.Store, id string, revision int64, m releases.Mutation) (releases.Detail, bool, error) {
	if !database.ValidID(id) || revision < 1 || m.Operation != "stage" || m.Recipe != nil || m.DraftID != "" || m.DraftRevision != 0 {
		return releases.Detail{}, false, ErrInvalid
	}
	var current int64
	if e := tx.QueryRow(ctx, "SELECT revision FROM builder_drafts WHERE id=$1 FOR SHARE", id).Scan(&current); e != nil {
		return releases.Detail{}, false, ErrNotFound
	}
	var replay bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM subscription_mutations WHERE actor_id=$1 AND idempotency_key=$2)", m.Actor, m.Key).Scan(&replay); e != nil {
		return releases.Detail{}, false, e
	}
	if current != revision && !replay {
		return releases.Detail{}, false, ErrConflict
	}
	d, e := s.ReadTx(ctx, tx, id, revision)
	if e != nil {
		return releases.Detail{}, false, e
	}
	m.DraftID = id
	m.DraftRevision = revision
	m.Recipe = &d.Document.Recipe
	return releasesStore.MutateTx(ctx, tx, m)
}
