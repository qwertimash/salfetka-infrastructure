// Package subscriptionsets stores shared composition and account assignments.
// An active assignment is intent, NOT an applied grant or a delivery credential.
// Callers must authorize operations and roll back their transaction on any error.
package subscriptionsets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/database"
)

var (
	ErrInvalid  = errors.New("subscription_set_invalid")
	ErrConflict = errors.New("subscription_set_conflict")
	ErrNotFound = errors.New("subscription_set_not_found")
	ErrCapacity = errors.New("subscription_set_capacity")
)

type Store struct{ Builder *builder.Store }

type Set struct {
	PublishedID *string          `json:"published_id"`
	ID          string           `json:"id"`
	Revision    int64            `json:"revision"`
	Document    builder.Document `json:"document"`
	UpdatedAt   time.Time        `json:"updated_at"`
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
type Save struct {
	Actor    string           `json:"-"`
	Key      string           `json:"-"`
	ID       string           `json:"id"`
	Revision int64            `json:"revision"`
	Document builder.Document `json:"document"`
}
type Assignment struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	SetID     string    `json:"set_id"`
	State     string    `json:"state"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Assign struct {
	Actor    string `json:"-"`
	Key      string `json:"-"`
	UserID   string `json:"user_id"`
	SetID    string `json:"set_id"`
	State    string `json:"state"`
	Revision int64  `json:"revision"`
}
type AssignmentPage struct {
	Items      []Assignment `json:"items"`
	NextCursor string       `json:"next_cursor"`
}

// Only opaque metadata goes in the replay ledger, never recipes or credentials.
type receipt struct {
	PublicationID string      `json:"publication_id,omitempty"`
	ID            string      `json:"id,omitempty"`
	Revision      int64       `json:"revision,omitempty"`
	Assignment    *Assignment `json:"assignment,omitempty"`
}

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

func begin(ctx context.Context, tx pgx.Tx, actor, key, operation string, m any) (receipt, []byte, bool, error) {
	var result receipt
	if !database.ValidID(actor) || !keyPattern.MatchString(key) {
		return result, nil, false, ErrInvalid
	}
	b, e := json.Marshal(m)
	if e != nil {
		return result, nil, false, ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte(operation + "\x00"))
	h.Write(b)
	clear(b)
	hash := h.Sum(nil)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,181))", actor+":"+key); e != nil {
		return result, nil, false, e
	}
	var old, body []byte
	e = tx.QueryRow(ctx, "SELECT request_hash,result FROM subscription_set_mutations WHERE actor_id=$1 AND idempotency_key=$2", actor, key).Scan(&old, &body)
	if errors.Is(e, pgx.ErrNoRows) {
		return result, hash, false, nil
	}
	if e != nil {
		return result, nil, false, e
	}
	if !bytes.Equal(old, hash) {
		return result, nil, false, ErrConflict
	}
	if e = json.Unmarshal(body, &result); e != nil {
		return result, nil, false, e
	}
	return result, hash, true, nil
}
func finish(ctx context.Context, tx pgx.Tx, actor, key, action, target string, hash []byte, r receipt) error {
	body, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO subscription_set_mutations(actor_id,idempotency_key,request_hash,result) VALUES($1,$2,$3,$4)", actor, key, hash, body); e != nil {
		return e
	}
	return audit.Append(ctx, tx, actor, action, target, "succeeded")
}
func (s *Store) ReadTx(ctx context.Context, tx pgx.Tx, id string, revision int64) (Set, error) {
	var out Set
	if !database.ValidID(id) || revision < 0 || s.Builder == nil {
		return out, ErrInvalid
	}
	var draft string
	var draftRevision int64
	e := tx.QueryRow(ctx, `SELECT s.id::text,v.revision,v.draft_id::text,v.draft_revision,v.created_at,s.published_id::text
 FROM subscription_sets s JOIN subscription_set_versions v ON v.set_id=s.id
 AND v.revision=CASE WHEN $2::bigint=0 THEN s.revision ELSE $2 END WHERE s.id=$1`, id, revision).Scan(&out.ID, &out.Revision, &draft, &draftRevision, &out.UpdatedAt, &out.PublishedID)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if e != nil {
		return out, e
	}
	d, e := s.Builder.ReadTx(ctx, tx, draft, draftRevision)
	out.Document = d.Document
	return out, e
}
func (s *Store) SaveTx(ctx context.Context, tx pgx.Tx, m Save) (Set, bool, error) {
	if s.Builder == nil || m.Revision < 0 || m.Document.Recipe.ExternalCredentials || (m.ID != "" && !database.ValidID(m.ID)) {
		return Set{}, false, ErrInvalid
	}
	r, hash, replay, e := begin(ctx, tx, m.Actor, m.Key, "save", m)
	if e != nil {
		return Set{}, false, e
	}
	if replay {
		out, e := s.ReadTx(ctx, tx, r.ID, r.Revision)
		return out, true, e
	}
	id := m.ID
	var draft string
	var revision, draftRevision int64
	if id == "" {
		if m.Revision != 0 {
			return Set{}, false, ErrConflict
		}
		id, e = database.NewID()
		if e != nil {
			return Set{}, false, e
		}
	} else {
		e = tx.QueryRow(ctx, "SELECT revision,draft_id::text FROM subscription_sets WHERE id=$1 FOR UPDATE", id).Scan(&revision, &draft)
		if errors.Is(e, pgx.ErrNoRows) {
			return Set{}, false, ErrNotFound
		}
		if e != nil {
			return Set{}, false, e
		}
		if revision != m.Revision {
			return Set{}, false, ErrConflict
		}
		if revision >= 1000 {
			return Set{}, false, ErrCapacity
		}
		// Legacy builder edits cannot change a pinned set version. Saving the set
		// explicitly writes a complete new document over the current draft head.
		if e = tx.QueryRow(ctx, "SELECT revision FROM builder_drafts WHERE id=$1 FOR UPDATE", draft).Scan(&draftRevision); e != nil {
			return Set{}, false, e
		}
	}
	derived := sha256.Sum256([]byte("subscription-set:" + m.Actor + ":" + m.Key))
	d, _, e := s.Builder.SaveTx(ctx, tx, builder.Mutation{Actor: m.Actor, Key: fmt.Sprintf("%x", derived), ID: draft, Revision: draftRevision, Document: m.Document})
	if e != nil {
		return Set{}, false, e
	}
	revision++
	if m.ID == "" {
		_, e = tx.Exec(ctx, "INSERT INTO subscription_sets(id,draft_id,revision) VALUES($1,$2,$3)", id, d.ID, revision)
	} else {
		_, e = tx.Exec(ctx, "UPDATE subscription_sets SET revision=$2,updated_at=clock_timestamp() WHERE id=$1", id, revision)
	}
	if e != nil {
		return Set{}, false, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO subscription_set_versions(set_id,revision,draft_id,draft_revision) VALUES($1,$2,$3,$4)", id, revision, d.ID, d.Revision); e != nil {
		return Set{}, false, e
	}
	if e = finish(ctx, tx, m.Actor, m.Key, "subscription_set.save", id, hash, receipt{ID: id, Revision: revision}); e != nil {
		return Set{}, false, e
	}
	out, e := s.ReadTx(ctx, tx, id, revision)
	return out, false, e
}

func (s *Store) ListTx(ctx context.Context, tx pgx.Tx, after string) (Page, error) {
	out := Page{Items: []Summary{}}
	if after != "" && !database.ValidID(after) {
		return out, ErrInvalid
	}
	rows, e := tx.Query(ctx, "SELECT id::text,revision FROM subscription_sets WHERE ($1='' OR id::text>$1) ORDER BY id LIMIT 51", after)
	if e != nil {
		return out, e
	}
	type head struct {
		id  string
		rev int64
	}
	heads := []head{}
	for rows.Next() {
		var h head
		if e = rows.Scan(&h.id, &h.rev); e != nil {
			rows.Close()
			return out, e
		}
		heads = append(heads, h)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return out, e
	}
	if len(heads) > 50 {
		heads = heads[:50]
		out.NextCursor = heads[49].id
	}
	for _, h := range heads {
		v, e := s.ReadTx(ctx, tx, h.id, h.rev)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, Summary{v.ID, v.Revision, v.Document.Title, v.UpdatedAt})
	}
	return out, nil
}

func (s *Store) AssignTx(ctx context.Context, tx pgx.Tx, m Assign) (Assignment, bool, error) {
	if !database.ValidID(m.UserID) || !database.ValidID(m.SetID) || m.Revision < 0 || (m.State != "active" && m.State != "revoked") {
		return Assignment{}, false, ErrInvalid
	}
	r, hash, replay, e := begin(ctx, tx, m.Actor, m.Key, "assign", m)
	if e != nil {
		return Assignment{}, false, e
	}
	if replay {
		if r.Assignment == nil {
			return Assignment{}, false, ErrInvalid
		}
		return *r.Assignment, true, nil
	}
	// Same lock as access state changes: an assignment cannot race past a
	// suspended/deleted account. Revoking intent remains allowed in either state.
	var state string
	e = tx.QueryRow(ctx, "SELECT state FROM access_users WHERE id=$1 FOR UPDATE", m.UserID).Scan(&state)
	if errors.Is(e, pgx.ErrNoRows) {
		return Assignment{}, false, ErrNotFound
	}
	if e != nil {
		return Assignment{}, false, e
	}
	if m.State == "active" && state != "active" {
		return Assignment{}, false, ErrConflict
	}
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM subscription_sets WHERE id=$1)", m.SetID).Scan(&exists); e != nil {
		return Assignment{}, false, e
	}
	if !exists {
		return Assignment{}, false, ErrNotFound
	}
	var a Assignment
	e = tx.QueryRow(ctx, `SELECT id::text,user_id::text,set_id::text,state,revision,updated_at FROM account_set_assignments WHERE user_id=$1 AND set_id=$2 FOR UPDATE`, m.UserID, m.SetID).Scan(&a.ID, &a.UserID, &a.SetID, &a.State, &a.Revision, &a.UpdatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		if m.Revision != 0 || m.State != "active" {
			return a, false, ErrConflict
		}
		a.ID, e = database.NewID()
		if e != nil {
			return a, false, e
		}
		_, e = tx.Exec(ctx, "INSERT INTO account_set_assignments(id,user_id,set_id,state,revision) VALUES($1,$2,$3,'active',1)", a.ID, m.UserID, m.SetID)
	} else if e == nil {
		if a.Revision != m.Revision {
			return a, false, ErrConflict
		}
		if a.Revision >= 9007199254740991 {
			return a, false, ErrCapacity
		}
		_, e = tx.Exec(ctx, "UPDATE account_set_assignments SET state=$2,revision=revision+1,token_hash=NULL,token_ciphertext=NULL,updated_at=clock_timestamp() WHERE id=$1", a.ID, m.State)
	}
	if e != nil {
		return Assignment{}, false, e
	}
	e = tx.QueryRow(ctx, "SELECT id::text,user_id::text,set_id::text,state,revision,updated_at FROM account_set_assignments WHERE id=$1", a.ID).Scan(&a.ID, &a.UserID, &a.SetID, &a.State, &a.Revision, &a.UpdatedAt)
	if e != nil {
		return a, false, e
	}
	action := "subscription_set.assign"
	if m.State == "revoked" {
		action = "subscription_set.unassign"
	}
	e = finish(ctx, tx, m.Actor, m.Key, action, a.ID, hash, receipt{Assignment: &a})
	return a, false, e
}

func (s *Store) AssignmentsTx(ctx context.Context, tx pgx.Tx, user, after string) (AssignmentPage, error) {
	out := AssignmentPage{Items: []Assignment{}}
	if !database.ValidID(user) || (after != "" && !database.ValidID(after)) {
		return out, ErrInvalid
	}
	rows, e := tx.Query(ctx, `SELECT id::text,user_id::text,set_id::text,state,revision,updated_at FROM account_set_assignments
 WHERE user_id=$1 AND ($2='' OR id::text>$2) ORDER BY id LIMIT 51`, user, after)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var a Assignment
		if e = rows.Scan(&a.ID, &a.UserID, &a.SetID, &a.State, &a.Revision, &a.UpdatedAt); e != nil {
			return out, e
		}
		out.Items = append(out.Items, a)
	}
	if len(out.Items) > 50 {
		out.Items = out.Items[:50]
		out.NextCursor = out.Items[49].ID
	}
	return out, rows.Err()
}
