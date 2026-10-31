package subscriptionsets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/releases"
)

type Publish struct {
	Actor    string `json:"-"`
	Key      string `json:"-"`
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}
type Publication struct {
	ID           string    `json:"id"`
	SetID        string    `json:"set_id"`
	Revision     int64     `json:"revision"`
	Current      bool      `json:"current"`
	Expected     int       `json:"expected_devices"`
	WaitingUsers int       `json:"users_without_device"`
	Published    int       `json:"published_devices"`
	Pending      int       `json:"pending_devices"`
	Retry        int       `json:"retry_devices"`
	Cancelled    int       `json:"cancelled_devices"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *Store) PublicationTx(ctx context.Context, tx pgx.Tx, id string) (Publication, error) {
	var p Publication
	if !database.ValidID(id) {
		return p, ErrInvalid
	}
	e := tx.QueryRow(ctx, `SELECT p.id::text,p.set_id::text,p.revision,s.published_id=p.id,p.created_at FROM set_publications p JOIN subscription_sets s ON s.id=p.set_id WHERE p.id=$1`, id).Scan(&p.ID, &p.SetID, &p.Revision, &p.Current, &p.CreatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	if e != nil {
		return p, e
	}
	e = tx.QueryRow(ctx, `SELECT count(*) FROM account_set_assignments a JOIN access_users u ON u.id=a.user_id JOIN access_entitlements e ON e.user_id=u.id JOIN access_devices d ON d.user_id=u.id
 WHERE a.set_id=$1 AND a.state='active' AND u.state='active' AND e.state='active' AND e.expires_at>clock_timestamp() AND d.state='registered'`, p.SetID).Scan(&p.Expected)
	if e != nil {
		return p, e
	}
	e = tx.QueryRow(ctx, `SELECT count(*) FROM account_set_assignments a WHERE a.set_id=$1 AND a.state='active' AND NOT EXISTS(SELECT 1 FROM access_devices d WHERE d.user_id=a.user_id AND d.state='registered')`, p.SetID).Scan(&p.WaitingUsers)
	if e != nil {
		return p, e
	}
	e = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE t.state='published' AND t.access_revision=u.revision),count(*) FILTER(WHERE t.state='pending' OR t.access_revision<>u.revision),count(*) FILTER(WHERE t.state='retry' AND t.access_revision=u.revision),count(*) FILTER(WHERE t.state='cancelled')
 FROM set_publication_targets t JOIN account_set_assignments a ON a.id=t.assignment_id JOIN access_users u ON u.id=t.user_id JOIN access_devices d ON d.id=t.device_id JOIN access_entitlements e ON e.user_id=u.id
 WHERE t.publication_id=$1 AND a.state='active' AND a.revision=t.assignment_revision AND u.state='active' AND d.state='registered' AND e.state='active' AND e.expires_at>clock_timestamp()`, id).Scan(&p.Published, &p.Pending, &p.Retry, &p.Cancelled)
	if e == nil && p.Expected > p.Published+p.Pending+p.Retry+p.Cancelled {
		p.Pending = p.Expected - p.Published - p.Retry - p.Cancelled
	}

	return p, e
}
func (s *Store) PublishTx(ctx context.Context, tx pgx.Tx, m Publish) (Publication, bool, error) {
	if !database.ValidID(m.ID) || m.Revision < 1 {
		return Publication{}, false, ErrInvalid
	}
	r, hash, replay, e := begin(ctx, tx, m.Actor, m.Key, "publish", m)
	if e != nil {
		return Publication{}, false, e
	}
	if replay {
		p, e := s.PublicationTx(ctx, tx, r.PublicationID)
		return p, true, e
	}
	var current int64
	var published *string
	e = tx.QueryRow(ctx, "SELECT revision,published_id::text FROM subscription_sets WHERE id=$1 FOR UPDATE", m.ID).Scan(&current, &published)
	if errors.Is(e, pgx.ErrNoRows) {
		return Publication{}, false, ErrNotFound
	}
	if e != nil {
		return Publication{}, false, e
	}
	if current != m.Revision {
		return Publication{}, false, ErrConflict
	}
	// Read/decrypt before accepting work; incomplete recipes can still fail per
	// device and are reported as retry, never replacing the previous release.
	if _, e = s.ReadTx(ctx, tx, m.ID, m.Revision); e != nil {
		return Publication{}, false, e
	}
	id, e := database.NewID()
	if e != nil {
		return Publication{}, false, e
	}
	e = tx.QueryRow(ctx, `INSERT INTO set_publications(id,set_id,revision,actor_id) VALUES($1,$2,$3,$4) ON CONFLICT(set_id,revision) DO NOTHING RETURNING id::text`, id, m.ID, m.Revision, m.Actor).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		e = tx.QueryRow(ctx, "SELECT id::text FROM set_publications WHERE set_id=$1 AND revision=$2", m.ID, m.Revision).Scan(&id)
	}
	if e != nil {
		return Publication{}, false, e
	}
	if _, e = tx.Exec(ctx, "UPDATE subscription_sets SET published_id=$2 WHERE id=$1", m.ID, id); e != nil {
		return Publication{}, false, e
	}
	if e = finish(ctx, tx, m.Actor, m.Key, "subscription_set.publish", m.ID, hash, receipt{PublicationID: id}); e != nil {
		return Publication{}, false, e
	}
	p, e := s.PublicationTx(ctx, tx, id)
	return p, false, e
}

// ScanTargets discovers newly assigned accounts/devices and access changes in
// bounded batches. Publication pointer and source documents remain immutable.
func (s *Store) ScanTargets(ctx context.Context) (int64, error) {
	tag, e := s.Builder.Pool.Exec(ctx, `INSERT INTO set_publication_targets(publication_id,assignment_id,assignment_revision,user_id,device_id,access_revision)
 SELECT s.published_id,a.id,a.revision,a.user_id,d.id,u.revision
 FROM subscription_sets s JOIN account_set_assignments a ON a.set_id=s.id
 JOIN access_users u ON u.id=a.user_id JOIN access_entitlements e ON e.user_id=u.id JOIN access_devices d ON d.user_id=u.id
 WHERE s.published_id IS NOT NULL AND a.state='active' AND u.state='active' AND e.state='active' AND e.expires_at>clock_timestamp() AND d.state='registered'
 AND NOT EXISTS(SELECT 1 FROM set_publication_targets t WHERE t.publication_id=s.published_id AND t.assignment_id=a.id AND t.assignment_revision=a.revision AND t.device_id=d.id AND t.access_revision=u.revision)
 ORDER BY s.id,a.id,d.id LIMIT 100
 ON CONFLICT(publication_id,assignment_id,assignment_revision,device_id) DO UPDATE SET state='pending',attempts=0,next_attempt=clock_timestamp(),last_code='',access_revision=excluded.access_revision,updated_at=clock_timestamp()
 WHERE set_publication_targets.access_revision<>excluded.access_revision`)
	return tag.RowsAffected(), e
}

// RunOne uses a locked durable target and a savepoint: only complete healthy
// releases commit. A crashed worker loses its transaction and the target remains
// retryable. No lease expiry can race another worker into publishing twice.
func (s *Store) RunOne(ctx context.Context, engine *releases.Store) (bool, error) {
	tx, e := s.Builder.Pool.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer database.Rollback(tx)
	var publication, assignment, user, device, actor, setID string
	var generation, revision, attempt int64
	e = tx.QueryRow(ctx, `SELECT t.publication_id::text,t.assignment_id::text,t.assignment_revision,t.user_id::text,t.device_id::text,p.actor_id::text,p.set_id::text,p.revision,t.attempts
 FROM set_publication_targets t JOIN set_publications p ON p.id=t.publication_id
 WHERE t.state IN ('pending','retry') AND t.next_attempt<=clock_timestamp()
 ORDER BY t.next_attempt,t.publication_id,t.assignment_id,t.device_id FOR UPDATE OF t SKIP LOCKED LIMIT 1`).Scan(&publication, &assignment, &generation, &user, &device, &actor, &setID, &revision, &attempt)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var current *string
	if e = tx.QueryRow(ctx, "SELECT published_id::text FROM subscription_sets WHERE id=$1 FOR SHARE", setID).Scan(&current); e != nil {
		return false, e
	}
	state, code := "cancelled", "superseded"
	if current != nil && *current == publication {
		state, code = "published", ""
		nested, e := tx.Begin(ctx)
		if e != nil {
			return false, e
		}
		e = s.applyTarget(ctx, nested, engine, publication, assignment, generation, user, device, actor, setID, revision, attempt)
		if e != nil {
			database.Rollback(nested)
			state, code = "retry", "publication_unavailable"
			if errors.Is(e, releases.ErrDenied) {
				state, code = "cancelled", "access_denied"
			}
			if errors.Is(e, releases.ErrConflict) {
				code = "publication_conflict"
			}
			if errors.Is(e, releases.ErrCapacity) {
				code = "release_capacity"
			}
		} else if e = nested.Commit(ctx); e != nil {
			return false, e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE set_publication_targets SET state=$5,last_code=$6,attempts=attempts+1,
 next_attempt=clock_timestamp()+make_interval(secs=>least(300,5*power(2,least(attempts,6)))::int),updated_at=clock_timestamp()
 WHERE publication_id=$1 AND assignment_id=$2 AND assignment_revision=$3 AND device_id=$4`, publication, assignment, generation, device, state, code)
	if e != nil {
		return false, e
	}
	return true, tx.Commit(ctx)
}
func (s *Store) applyTarget(ctx context.Context, tx pgx.Tx, engine *releases.Store, publication, assignment string, generation int64, user, device, actor, setID string, revision, attempt int64) error {
	document, e := s.ReadTx(ctx, tx, setID, revision)
	if e != nil {
		return e
	}
	scoped := *engine
	scoped.AssignmentID = assignment
	scoped.AssignmentRevision = generation
	detail, e := scoped.DetailTx(ctx, tx, user, device)
	if e != nil && !errors.Is(e, releases.ErrUnavailable) {
		return e
	}
	mutate := func(op string, recipe *releases.Recipe, release string) error {
		m := releases.Mutation{Actor: actor, Key: fmt.Sprintf("%s:%s:%d:%s:%d:%s", publication, device, generation, op, attempt, "set"), Operation: op, UserID: user, DeviceID: device, Revision: detail.Subscription.Revision, TokenRevision: detail.Subscription.TokenRevision, Recipe: recipe, ReleaseID: release}
		var err error
		detail, _, err = scoped.MutateTx(ctx, tx, m)
		return err
	}
	document.Document.Recipe.Title = document.Document.Title
	if e = mutate("stage", &document.Document.Recipe, ""); e != nil {
		return e
	}
	release := detail.Releases[0].ID
	if e = mutate("publish", nil, release); e != nil {
		return e
	}
	if detail.Subscription.ActiveRelease == nil || *detail.Subscription.ActiveRelease != release {
		return releases.ErrUnavailable
	}
	if !detail.Subscription.TokenActive {
		if e = mutate("rotate", nil, ""); e != nil {
			return e
		}
	}
	return nil
}

// TargetsTx exposes safe per-device progress; opaque IDs and fixed error codes,
// no compiled artifacts, bearer tokens or raw node/SQL error text.
type Target struct {
	AssignmentID string `json:"assignment_id"`
	Generation   int64  `json:"assignment_revision"`
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	State        string `json:"state"`
	Code         string `json:"code"`
	Attempts     int64  `json:"attempts"`
}
type TargetPage struct {
	Items      []Target `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

func (s *Store) TargetsTx(ctx context.Context, tx pgx.Tx, publication, after string) (TargetPage, error) {
	out := TargetPage{Items: []Target{}}
	if !database.ValidID(publication) || len(after) > 120 {
		return out, ErrInvalid
	}
	// Cursor is a bounded opaque tuple emitted by this endpoint, not SQL.
	rows, e := tx.Query(ctx, `SELECT assignment_id::text,assignment_revision,user_id::text,device_id::text,state,last_code,attempts,
 assignment_id::text||':'||lpad(assignment_revision::text,16,'0')||':'||device_id::text AS cursor
 FROM set_publication_targets WHERE publication_id=$1 AND (assignment_id::text||':'||lpad(assignment_revision::text,16,'0')||':'||device_id::text)>$2
 ORDER BY cursor LIMIT 51`, publication, after)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	var cursor string
	for rows.Next() {
		var t Target
		var c string
		if e = rows.Scan(&t.AssignmentID, &t.Generation, &t.UserID, &t.DeviceID, &t.State, &t.Code, &t.Attempts, &c); e != nil {
			return out, e
		}
		if len(out.Items) == 50 {
			out.NextCursor = cursor
			break
		}
		out.Items = append(out.Items, t)
		cursor = c
	}
	return out, rows.Err()
}
