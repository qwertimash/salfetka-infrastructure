// Package catalog stores reviewed imports separately from live VPN policies.
package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/secrets"
)

var ErrInvalid = errors.New("source_invalid")
var ErrNotFound = errors.New("source_not_found")
var ErrConflict = errors.New("source_conflict")
var ErrRevision = errors.New("source_revision")
var ErrCapacity = errors.New("source_capacity")
var ErrExpired = errors.New("source_draft_expired")

type Store struct {
	Pool  *pgxpool.Pool
	Vault *secrets.Vault
	fetch func(context.Context, string) (importer.FetchResult, error)
}

func New(pool *pgxpool.Pool, v *secrets.Vault) *Store {
	return &Store{Pool: pool, Vault: v, fetch: importer.Fetch}
}

type Input struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Input string `json:"input"`
}
type privateDocument struct {
	Name         string
	Kind         string
	URL          string
	Raw          []byte
	Normalized   json.RawMessage
	HeaderExpiry *time.Time
	Userinfo     []string
}
type Prepared struct {
	document privateDocument
	Preview  importer.Preview
}
type Draft struct {
	ID        string           `json:"id"`
	Preview   importer.Preview `json:"preview"`
	ExpiresAt time.Time        `json:"expires_at"`
}
type Version struct {
	ID        string           `json:"id"`
	Preview   importer.Preview `json:"preview"`
	CreatedAt time.Time        `json:"created_at"`
}
type Source struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Revision    int64      `json:"revision"`
	Paused      bool       `json:"paused"`
	ErrorCode   *string    `json:"error_code"`
	NextFetchAt *time.Time `json:"next_fetch_at"`
	Current     *Version   `json:"current"`
	Candidate   *Version   `json:"candidate"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func validName(s string) bool {
	if len([]rune(s)) < 2 || len([]rune(s)) > 80 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (s *Store) Prepare(ctx context.Context, in Input) (Prepared, error) {
	if !validName(in.Name) || (in.Kind != "upload" && in.Kind != "url") || len(in.Input) == 0 || len(in.Input) > importer.MaxBytes {
		return Prepared{}, ErrInvalid
	}
	d := privateDocument{Name: in.Name, Kind: in.Kind, Raw: []byte(in.Input)}
	if in.Kind == "url" {
		if e := importer.ValidateURL(in.Input); e != nil {
			return Prepared{}, e
		}
		f, e := s.fetch(ctx, in.Input)
		if e != nil {
			return Prepared{}, e
		}
		d.URL = in.Input
		d.Raw = f.Data
		d.HeaderExpiry = f.ExpiresAt
		d.Userinfo = f.Userinfo
	}
	return prepare(d, time.Now())
}
func prepare(d privateDocument, now time.Time) (Prepared, error) {
	r, e := importer.Parse(d.Raw, now)
	if e != nil {
		return Prepared{}, e
	}
	if d.HeaderExpiry != nil {
		if !d.HeaderExpiry.After(now) {
			return Prepared{}, importer.Error("source_expired")
		}
		if r.Preview.SubscriptionExpiresAt == nil || d.HeaderExpiry.Before(*r.Preview.SubscriptionExpiresAt) {
			r.Preview.SubscriptionExpiresAt = d.HeaderExpiry
		}
	}
	d.Normalized = r.Normalized
	// Bind the revision to raw bytes plus upstream expiry, not just the body.
	h := sha256.New()
	h.Write(d.Raw)
	provenance, _ := json.Marshal(d.Userinfo)
	h.Write([]byte("\x00"))
	h.Write(provenance)
	if d.HeaderExpiry != nil {
		h.Write([]byte("\x00" + d.HeaderExpiry.Format(time.RFC3339Nano)))
	}
	r.Preview.Digest = hex.EncodeToString(h.Sum(nil))
	return Prepared{document: d, Preview: r.Preview}, nil
}
func (s *Store) DraftTx(ctx context.Context, tx pgx.Tx, actor string, p Prepared) (Draft, error) {
	if !database.ValidID(actor) {
		return Draft{}, ErrInvalid
	}
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,12))", actor); e != nil {
		return Draft{}, e
	}
	if _, e := tx.Exec(ctx, "DELETE FROM catalog_drafts WHERE expires_at<clock_timestamp()"); e != nil {
		return Draft{}, e
	}
	var count int
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM catalog_drafts WHERE actor_id=$1 AND source_id IS NULL", actor).Scan(&count); e != nil {
		return Draft{}, e
	}
	if count >= 32 {
		return Draft{}, ErrCapacity
	}
	id, e := database.NewID()
	if e != nil {
		return Draft{}, e
	}
	b, e := json.Marshal(p.document)
	if e != nil {
		return Draft{}, ErrInvalid
	}
	defer clear(b)
	cipher, e := s.Vault.SealSource(b, "draft:"+actor+":"+id)
	if e != nil {
		return Draft{}, e
	}
	preview, _ := json.Marshal(p.Preview)
	d := Draft{ID: id, Preview: p.Preview}
	e = tx.QueryRow(ctx, `INSERT INTO catalog_drafts(id,actor_id,body_ciphertext,preview) VALUES($1,$2,$3,$4) RETURNING expires_at`, id, actor, cipher, preview).Scan(&d.ExpiresAt)
	return d, e
}
func (s *Store) document(cipher []byte, aad string) (privateDocument, error) {
	b, e := s.Vault.OpenSource(cipher, aad)
	if e != nil {
		return privateDocument{}, e
	}
	defer clear(b)
	var d privateDocument
	if json.Unmarshal(b, &d) != nil {
		return privateDocument{}, secrets.ErrUnavailable
	}
	return d, nil
}
func (s *Store) addVersion(ctx context.Context, tx pgx.Tx, source string, p Prepared) (string, error) {
	var count int
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM catalog_versions WHERE source_id=$1", source).Scan(&count); e != nil {
		return "", e
	}
	if count >= 200 {
		return "", ErrCapacity
	}
	id, e := database.NewID()
	if e != nil {
		return "", e
	}
	b, e := json.Marshal(p.document)
	if e != nil {
		return "", e
	}
	defer clear(b)
	cipher, e := s.Vault.SealSource(b, "version:"+source+":"+id)
	if e != nil {
		return "", e
	}
	preview, _ := json.Marshal(p.Preview)
	_, e = tx.Exec(ctx, `INSERT INTO catalog_versions(id,source_id,body_ciphertext,preview,digest) VALUES($1,$2,$3,$4,$5)`, id, source, cipher, preview, p.Preview.Digest)
	return id, e
}

const sourceColumns = `s.id::text,s.name,s.kind,s.revision,s.paused,s.error_code,s.next_fetch_at,s.updated_at,
 c.id::text,c.preview,c.created_at,n.id::text,n.preview,n.created_at`
const sourceJoin = ` FROM catalog_sources s LEFT JOIN catalog_versions c ON c.id=s.current_version LEFT JOIN catalog_versions n ON n.id=s.candidate_version `

func scan(row pgx.Row) (Source, error) {
	var s Source
	var c, n *string
	var cp, np []byte
	var ct, nt *time.Time
	e := row.Scan(&s.ID, &s.Name, &s.Kind, &s.Revision, &s.Paused, &s.ErrorCode, &s.NextFetchAt, &s.UpdatedAt, &c, &cp, &ct, &n, &np, &nt)
	if errors.Is(e, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	if e != nil {
		return s, e
	}
	if c != nil {
		s.Current = &Version{ID: *c, CreatedAt: *ct}
		if json.Unmarshal(cp, &s.Current.Preview) != nil {
			return s, secrets.ErrUnavailable
		}
	}
	if n != nil {
		s.Candidate = &Version{ID: *n, CreatedAt: *nt}
		if json.Unmarshal(np, &s.Candidate.Preview) != nil {
			return s, secrets.ErrUnavailable
		}
	}
	return s, nil
}
func (s *Store) GetTx(ctx context.Context, tx pgx.Tx, id string) (Source, error) {
	if !database.ValidID(id) {
		return Source{}, ErrInvalid
	}
	return scan(tx.QueryRow(ctx, "SELECT "+sourceColumns+sourceJoin+" WHERE s.id=$1", id))
}
func (s *Store) ListTx(ctx context.Context, tx pgx.Tx) ([]Source, error) {
	rows, e := tx.Query(ctx, "SELECT "+sourceColumns+sourceJoin+" ORDER BY s.created_at DESC,s.id LIMIT 201")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	list := []Source{}
	for rows.Next() {
		v, e := scan(rows)
		if e != nil {
			return nil, e
		}
		list = append(list, v)
	}
	return list, rows.Err()
}

func (s *Store) VersionsTx(ctx context.Context, tx pgx.Tx, id string) ([]Version, error) {
	if _, e := s.GetTx(ctx, tx, id); e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, "SELECT id::text,preview,created_at FROM catalog_versions WHERE source_id=$1 ORDER BY created_at DESC,id LIMIT 200", id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		var v Version
		var raw []byte
		if e = rows.Scan(&v.ID, &raw, &v.CreatedAt); e != nil {
			return nil, e
		}
		if json.Unmarshal(raw, &v.Preview) != nil {
			return nil, secrets.ErrUnavailable
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type Mutation struct {
	Actor     string `json:"-"`
	Key       string `json:"-"`
	Operation string `json:"operation"`
	ID        string `json:"id"`
	Revision  int64  `json:"revision"`
	DraftID   string `json:"draft_id"`
	VersionID string `json:"version_id"`
	Paused    bool   `json:"paused"`
}

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

func (s *Store) MutateTx(ctx context.Context, tx pgx.Tx, m Mutation) (Source, bool, error) {
	if !database.ValidID(m.Actor) || !keyPattern.MatchString(m.Key) {
		return Source{}, false, ErrInvalid
	}
	raw, _ := json.Marshal(m)
	hash := sha256.Sum256(raw)
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,13))", m.Actor+":"+m.Key); e != nil {
		return Source{}, false, e
	}
	var previous, body []byte
	e := tx.QueryRow(ctx, "SELECT request_hash,result FROM catalog_mutations WHERE actor_id=$1 AND idempotency_key=$2", m.Actor, m.Key).Scan(&previous, &body)
	if e == nil {
		if string(previous) != string(hash[:]) {
			return Source{}, false, ErrConflict
		}
		var out Source
		if json.Unmarshal(body, &out) != nil {
			return Source{}, false, secrets.ErrUnavailable
		}
		return out, true, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return Source{}, false, e
	}
	target := m.ID
	if m.Operation == "create" {
		if !database.ValidID(m.DraftID) || m.ID != "" || m.Revision != 0 || m.VersionID != "" || m.Paused {
			return Source{}, false, ErrInvalid
		}
		var cipher []byte
		var expiry time.Time
		var used *string
		e = tx.QueryRow(ctx, `SELECT body_ciphertext,expires_at,source_id::text FROM catalog_drafts WHERE id=$1 AND actor_id=$2 FOR UPDATE`, m.DraftID, m.Actor).Scan(&cipher, &expiry, &used)
		if errors.Is(e, pgx.ErrNoRows) {
			return Source{}, false, ErrNotFound
		}
		if e != nil {
			return Source{}, false, e
		}
		if used != nil {
			return Source{}, false, ErrConflict
		}
		if !expiry.After(time.Now()) {
			return Source{}, false, ErrExpired
		}
		doc, e := s.document(cipher, "draft:"+m.Actor+":"+m.DraftID)
		if e != nil {
			return Source{}, false, e
		}
		p, e := prepare(doc, time.Now())
		if e != nil {
			return Source{}, false, e
		}
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(12012012)"); e != nil {
			return Source{}, false, e
		}
		var count int
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM catalog_sources").Scan(&count); e != nil {
			return Source{}, false, e
		}
		if count >= 200 {
			return Source{}, false, ErrCapacity
		}
		target, e = database.NewID()
		if e != nil {
			return Source{}, false, e
		}
		var urlCipher []byte
		if doc.Kind == "url" {
			urlCipher, e = s.Vault.SealSource([]byte(doc.URL), "source-url:"+target)
			if e != nil {
				return Source{}, false, e
			}
		}
		_, e = tx.Exec(ctx, `INSERT INTO catalog_sources(id,name,kind,url_ciphertext,next_fetch_at) VALUES($1,$2,$3,$4,CASE WHEN $3='url' THEN clock_timestamp()+interval '1 hour' END)`, target, doc.Name, doc.Kind, urlCipher)
		if e != nil {
			return Source{}, false, e
		}
		version, e := s.addVersion(ctx, tx, target, p)
		if e != nil {
			return Source{}, false, e
		}
		if _, e = tx.Exec(ctx, "UPDATE catalog_sources SET current_version=$2 WHERE id=$1", target, version); e != nil {
			return Source{}, false, e
		}
		if _, e = tx.Exec(ctx, "UPDATE catalog_drafts SET source_id=$2 WHERE id=$1", m.DraftID, target); e != nil {
			return Source{}, false, e
		}
	} else {
		if !database.ValidID(target) || m.Revision < 1 || m.DraftID != "" {
			return Source{}, false, ErrInvalid
		}
		var revision int64
		var candidate *string
		var kind string
		e = tx.QueryRow(ctx, "SELECT revision,candidate_version::text,kind FROM catalog_sources WHERE id=$1 FOR UPDATE", target).Scan(&revision, &candidate, &kind)
		if errors.Is(e, pgx.ErrNoRows) {
			return Source{}, false, ErrNotFound
		}
		if e != nil {
			return Source{}, false, e
		}
		if revision != m.Revision {
			return Source{}, false, ErrRevision
		}
		switch m.Operation {
		case "accept":
			if candidate == nil || *candidate != m.VersionID || m.Paused {
				return Source{}, false, ErrConflict
			}
			var cipher []byte
			e = tx.QueryRow(ctx, "SELECT body_ciphertext FROM catalog_versions WHERE source_id=$1 AND id=$2", target, m.VersionID).Scan(&cipher)
			if e != nil {
				return Source{}, false, e
			}
			doc, e := s.document(cipher, "version:"+target+":"+m.VersionID)
			if e != nil {
				return Source{}, false, e
			}
			if _, e = prepare(doc, time.Now()); e != nil {
				return Source{}, false, e
			}
			_, e = tx.Exec(ctx, "UPDATE catalog_sources SET current_version=candidate_version,candidate_version=NULL WHERE id=$1", target)
		case "refresh":
			if kind != "url" || m.VersionID != "" || m.Paused {
				return Source{}, false, ErrInvalid
			}
			_, e = tx.Exec(ctx, "UPDATE catalog_sources SET next_fetch_at=clock_timestamp(),paused=false,lease_id=NULL,lease_until=NULL WHERE id=$1", target)
		case "pause":
			if kind != "url" || m.VersionID != "" {
				return Source{}, false, ErrInvalid
			}
			_, e = tx.Exec(ctx, "UPDATE catalog_sources SET paused=$2,lease_id=NULL,lease_until=NULL WHERE id=$1", target, m.Paused)
		default:
			return Source{}, false, ErrInvalid
		}
		if e != nil {
			return Source{}, false, e
		}
		if _, e = tx.Exec(ctx, "UPDATE catalog_sources SET revision=revision+1,updated_at=clock_timestamp() WHERE id=$1", target); e != nil {
			return Source{}, false, e
		}
	}
	out, e := s.GetTx(ctx, tx, target)
	if e != nil {
		return Source{}, false, e
	}
	body, _ = json.Marshal(out)
	if _, e = tx.Exec(ctx, "INSERT INTO catalog_mutations(actor_id,idempotency_key,request_hash,result) VALUES($1,$2,$3,$4)", m.Actor, m.Key, hash[:], body); e != nil {
		return Source{}, false, e
	}
	if e = audit.Append(ctx, tx, m.Actor, "source."+m.Operation, target, "accepted"); e != nil {
		return Source{}, false, e
	}
	return out, false, nil
}
