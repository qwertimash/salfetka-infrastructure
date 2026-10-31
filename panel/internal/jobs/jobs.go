// Package jobs is the durable local outbox. B1 dispatches only system.check;
// callers cannot supply shell commands, URLs or arbitrary executable work.
package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
)

var (
	ErrInvalid   = errors.New("job_invalid")
	ErrConflict  = errors.New("idempotency_conflict")
	ErrNotFound  = errors.New("job_not_found")
	ErrLeaseLost = errors.New("lease_lost")
)

type Job struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	MaxAttempts int             `json:"max_attempts"`
	ErrorCode   string          `json:"error_code,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	AvailableAt time.Time       `json:"available_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	ActorID     string          `json:"-"`
	Payload     json.RawMessage `json:"-"`
	PayloadHash string          `json:"-"`
	LeaseToken  string          `json:"-"`
	WorkerID    string          `json:"-"`
	LeaseUntil  *time.Time      `json:"-"`
}

type Store struct {
	Pool          *pgxpool.Pool
	LeaseDuration time.Duration
	RetryDelay    time.Duration
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{Pool: pool, LeaseDuration: 30 * time.Second, RetryDelay: time.Second}
}

const columns = `id::text,kind,status,attempts,max_attempts,COALESCE(error_code,''),created_at,updated_at,available_at,finished_at,actor_id,payload,payload_sha256,COALESCE(lease_token::text,''),COALESCE(worker_id,''),lease_until`

type scanner interface{ Scan(...any) error }

func scan(row scanner) (Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.Kind, &j.Status, &j.Attempts, &j.MaxAttempts, &j.ErrorCode, &j.CreatedAt, &j.UpdatedAt, &j.AvailableAt, &j.FinishedAt, &j.ActorID, &j.Payload, &j.PayloadHash, &j.LeaseToken, &j.WorkerID, &j.LeaseUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return j, err
}

var safeKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func actorOK(id string) bool { return database.ValidID(id) || id == "system" }

// Only {} is a valid B1 payload. Parse other bounded objects solely to detect an
// idempotency conflict with an existing request; they can never be inserted.
// Reject duplicate keys rather than accepting a last-write-wins interpretation.
func canonical(payload json.RawMessage) ([]byte, string, bool, error) {
	if len(payload) == 0 || len(payload) > 2048 || !utf8.Valid(payload) {
		return nil, "", false, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, "", false, ErrInvalid
	}
	obj := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, "", false, ErrInvalid
		}
		k, ok := t.(string)
		if !ok {
			return nil, "", false, ErrInvalid
		}
		if _, exists := obj[k]; exists {
			return nil, "", false, ErrInvalid
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, "", false, ErrInvalid
		}
		obj[k] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, "", false, ErrInvalid
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return nil, "", false, ErrInvalid
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, "", false, ErrInvalid
	}
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), len(obj) == 0, nil
}

// Enqueue and its audit record commit atomically. A uniqueness constraint resolves
// simultaneous retries; the loser reads the winner in the following READ COMMITTED
// statement and compares the canonical payload hash.
func (s *Store) Enqueue(ctx context.Context, actorID, kind, key string, payload json.RawMessage) (Job, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Job{}, false, err
	}
	defer database.Rollback(tx)
	j, created, err := s.EnqueueTx(ctx, tx, actorID, kind, key, payload)
	if err != nil {
		return Job{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Job{}, false, err
	}
	return j, created, nil
}

// EnqueueTx lets the HTTP caller hold its verified session/role lock through the
// very same job+audit commit. The caller owns commit/rollback; no nested pool
// connection or independent authorization logic is introduced here.
func (s *Store) EnqueueTx(ctx context.Context, tx pgx.Tx, actorID, kind, key string, payload json.RawMessage) (Job, bool, error) {
	if !actorOK(actorID) || kind != "system.check" || !safeKey.MatchString(key) {
		return Job{}, false, ErrInvalid
	}
	b, hash, allowed, err := canonical(payload)
	if err != nil {
		return Job{}, false, err
	}
	// Invalid new requests never enter the outbox. A changed retry receives the
	// promised conflict, rather than silently adopting a different payload.
	if !allowed {
		j, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM jobs WHERE actor_id=$1 AND kind=$2 AND idempotency_key=$3`, actorID, kind, key))
		if err == nil && j.PayloadHash != hash {
			return Job{}, false, ErrConflict
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return Job{}, false, err
		}
		return Job{}, false, ErrInvalid
	}
	id, err := database.NewID()
	if err != nil {
		return Job{}, false, err
	}
	j, err := scan(tx.QueryRow(ctx, `INSERT INTO jobs(id,actor_id,kind,idempotency_key,payload,payload_sha256)
VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(actor_id,kind,idempotency_key) DO NOTHING RETURNING `+columns, id, actorID, kind, key, b, hash))
	created := err == nil
	if errors.Is(err, ErrNotFound) {
		j, err = scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM jobs WHERE actor_id=$1 AND kind=$2 AND idempotency_key=$3`, actorID, kind, key))
	}
	if err != nil {
		return Job{}, false, err
	}
	if j.PayloadHash != hash {
		return Job{}, false, ErrConflict
	}
	if created {
		if err = audit.Append(ctx, tx, actorID, "job.enqueued", j.ID, "accepted"); err != nil {
			return Job{}, false, err
		}
	}
	return j, created, nil
}

func (s *Store) Get(ctx context.Context, id string) (Job, error) {
	if !database.ValidID(id) {
		return Job{}, ErrInvalid
	}
	return scan(s.Pool.QueryRow(ctx, `SELECT `+columns+` FROM jobs WHERE id=$1`, id))
}

func (s *Store) List(ctx context.Context, limit int, beforeID string) ([]Job, error) {
	if limit < 1 || limit > 100 || (beforeID != "" && !database.ValidID(beforeID)) {
		return nil, ErrInvalid
	}
	var before time.Time
	if beforeID != "" {
		j, err := s.Get(ctx, beforeID)
		if err != nil {
			return nil, err
		}
		before = j.CreatedAt
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+columns+` FROM jobs WHERE $1='' OR (created_at,id)<($2,NULLIF($1,'')::uuid)
ORDER BY created_at DESC,id DESC LIMIT $3`, beforeID, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Job{}
	for rows.Next() {
		j, err := scan(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, j)
	}
	return list, rows.Err()
}

func (s *Store) Counts(ctx context.Context) (map[string]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT status,count(*) FROM jobs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int64{"pending": 0, "running": 0, "succeeded": 0, "failed": 0}
	for rows.Next() {
		var k string
		var n int64
		if err = rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		counts[k] = n
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

func (s *Store) duration() (int64, error) {
	if s.LeaseDuration < time.Millisecond || s.LeaseDuration > 5*time.Minute {
		return 0, ErrInvalid
	}
	return s.LeaseDuration.Microseconds(), nil
}

// Claim never holds a transaction while executing work. SKIP LOCKED allows
// independent claimers; each claim increments attempts and gets a new token.
func (s *Store) Claim(ctx context.Context, workerID string) (*Job, error) {
	lease, err := s.duration()
	if err != nil || !safeKey.MatchString(workerID) {
		return nil, ErrInvalid
	}
	token, err := database.NewID()
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer database.Rollback(tx)
	// A worker dying on its last attempt cannot strand a job as running forever.
	rows, err := tx.Query(ctx, `WITH exhausted AS (
SELECT id FROM jobs WHERE ((status='running' AND lease_until<=clock_timestamp()) OR status='pending') AND attempts>=max_attempts
ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 32)
UPDATE jobs SET status='failed',error_code='lease_expired',worker_id=NULL,lease_token=NULL,lease_until=NULL,
finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id IN(SELECT id FROM exhausted) RETURNING id::text`)
	if err != nil {
		return nil, err
	}
	dead := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		dead = append(dead, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, id := range dead {
		if err = audit.Append(ctx, tx, "worker", "job.failed", id, "failed"); err != nil {
			return nil, err
		}
	}
	j, err := scan(tx.QueryRow(ctx, `UPDATE jobs SET status='running',attempts=attempts+1,worker_id=$1,lease_token=$2,
lease_until=clock_timestamp()+($3 * interval '1 microsecond'),updated_at=clock_timestamp(),error_code=NULL
WHERE id=(SELECT id FROM jobs WHERE attempts<max_attempts AND
((status='pending' AND available_at<=clock_timestamp()) OR (status='running' AND lease_until<=clock_timestamp()))
ORDER BY available_at,created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+columns, workerID, token, lease))
	if errors.Is(err, ErrNotFound) {
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &j, nil
}

func leaseIDs(id, token string) bool { return database.ValidID(id) && database.ValidID(token) }

func (s *Store) Renew(ctx context.Context, id, token string) error {
	lease, err := s.duration()
	if err != nil || !leaseIDs(id, token) {
		return ErrInvalid
	}
	r, err := s.Pool.Exec(ctx, `UPDATE jobs SET lease_until=clock_timestamp()+($3 * interval '1 microsecond'),updated_at=clock_timestamp()
WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>clock_timestamp()`, id, token, lease)
	if err != nil {
		return err
	}
	if r.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}

// Complete linearizes the fenced completion while the lease is still valid.
// The sole B1 effect and the audit commit in this same transaction. There is no
// external side effect or claim that a future remote API provides exactly once.
func (s *Store) Complete(ctx context.Context, id, token string) error {
	if !leaseIDs(id, token) {
		return ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer database.Rollback(tx)
	j, err := scan(tx.QueryRow(ctx, `UPDATE jobs SET status='succeeded',worker_id=NULL,lease_token=NULL,lease_until=NULL,
error_code=NULL,finished_at=clock_timestamp(),updated_at=clock_timestamp()
WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>clock_timestamp() RETURNING `+columns, id, token))
	if errors.Is(err, ErrNotFound) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if j.Kind != "system.check" || !bytes.Equal(bytes.TrimSpace(j.Payload), []byte("{}")) {
		return ErrInvalid
	}
	if _, err = tx.Exec(ctx, `INSERT INTO system_check_results(job_id,schema_version)
SELECT $1,max(version) FROM schema_migrations ON CONFLICT(job_id) DO NOTHING`, j.ID); err != nil {
		return err
	}
	if err = audit.Append(ctx, tx, "worker", "job.succeeded", j.ID, "succeeded"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Fail(ctx context.Context, id, token, errorCode string) error {
	if !leaseIDs(id, token) || (errorCode != "system_check_failed" && errorCode != "worker_error") {
		return ErrInvalid
	}
	if s.RetryDelay < 0 || s.RetryDelay > time.Minute {
		return ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer database.Rollback(tx)
	j, err := scan(tx.QueryRow(ctx, `UPDATE jobs SET status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'pending' END,
worker_id=NULL,lease_token=NULL,lease_until=NULL,error_code=$3,
finished_at=CASE WHEN attempts>=max_attempts THEN clock_timestamp() ELSE NULL END,
available_at=clock_timestamp()+($4 * interval '1 microsecond'),updated_at=clock_timestamp()
WHERE id=$1 AND lease_token=$2 AND status='running' AND lease_until>clock_timestamp() RETURNING `+columns, id, token, errorCode, s.RetryDelay.Microseconds()))
	if errors.Is(err, ErrNotFound) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	action := "job.retry_scheduled"
	if j.Status == "failed" {
		action = "job.failed"
	}
	if err = audit.Append(ctx, tx, "worker", action, j.ID, "failed"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RunOne(ctx context.Context, workerID string) (bool, error) {
	j, err := s.Claim(ctx, workerID)
	if err != nil {
		return false, err
	}
	if j == nil {
		return false, nil
	}
	if err = s.Complete(ctx, j.ID, j.LeaseToken); err != nil {
		if !errors.Is(err, ErrLeaseLost) {
			_ = s.Fail(ctx, j.ID, j.LeaseToken, "system_check_failed")
		}
		return true, err
	}
	return true, nil
}
