package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
)

func TestPayloadAndPublicJobPrivacy(t *testing.T) {
	_, hash, allowed, err := canonical(json.RawMessage(" { \n } "))
	if err != nil || !allowed {
		t.Fatal("empty object rejected")
	}
	_, same, _, _ := canonical(json.RawMessage("{}"))
	if same != hash {
		t.Fatal("canonical retry changed hash")
	}
	for _, raw := range []string{"", "null", "[]", "{} {}", `{ "x":1,"x":2 }`, "{", "\xff"} {
		if _, _, _, err = canonical(json.RawMessage(raw)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid payload accepted %q", raw)
		}
	}
	if _, _, allowed, err = canonical(json.RawMessage(`{"future":true}`)); err != nil || allowed {
		t.Fatal("future payload not held behind validation")
	}
	b, err := json.Marshal(Job{ID: "safe", ActorID: "PRIVATE_ACTOR", Payload: json.RawMessage(`{"secret":"PRIVATE_PAYLOAD"}`), PayloadHash: "PRIVATE_HASH", LeaseToken: "PRIVATE_TOKEN", WorkerID: "PRIVATE_WORKER"})
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]any
	if err = json.Unmarshal(b, &public); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"actor_id", "payload", "payload_hash", "lease_token", "worker_id", "lease_until"} {
		if _, ok := public[key]; ok {
			t.Fatal("private field exposed", key)
		}
	}
}

func enqueue(t *testing.T, s *Store, key string) Job {
	t.Helper()
	j, created, err := s.Enqueue(context.Background(), "system", "system.check", key, json.RawMessage(`{}`))
	if err != nil || !created {
		t.Fatal("enqueue", err)
	}
	return j
}
func claim(t *testing.T, s *Store, worker string) *Job {
	t.Helper()
	j, err := s.Claim(context.Background(), worker)
	if err != nil || j == nil {
		t.Fatal("claim", err)
	}
	return j
}
func count(t *testing.T, p *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := p.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresConcurrentDuplicateAndConflict(t *testing.T) {
	p := dbtest.New(t)
	s := New(p)
	ctx := context.Background()
	var wg sync.WaitGroup
	start := make(chan struct{})
	type result struct {
		j       Job
		created bool
		err     error
	}
	out := make(chan result, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			j, c, e := s.Enqueue(ctx, "system", "system.check", "same-key", json.RawMessage(" { } "))
			out <- result{j, c, e}
		}()
	}
	close(start)
	wg.Wait()
	close(out)
	created := 0
	id := ""
	for r := range out {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.created {
			created++
		}
		if id != "" && id != r.j.ID {
			t.Fatal("duplicate jobs")
		}
		id = r.j.ID
	}
	if created != 1 {
		t.Fatal("multiple creation results", created)
	}
	if count(t, p, `SELECT count(*) FROM jobs`) != 1 || count(t, p, `SELECT count(*) FROM audit_events WHERE action='job.enqueued'`) != 1 {
		t.Fatal("outbox/audit duplicated")
	}
	if _, _, err := s.Enqueue(ctx, "system", "system.check", "same-key", json.RawMessage(`{"changed":true}`)); !errors.Is(err, ErrConflict) {
		t.Fatal("changed retry not conflict", err)
	}
	if _, _, err := s.Enqueue(ctx, "system", "system.check", "new-key", json.RawMessage(`{"changed":true}`)); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown executable payload accepted", err)
	}
	actor, _ := database.NewID()
	if _, made, err := s.Enqueue(ctx, actor, "system.check", "same-key", json.RawMessage(`{}`)); err != nil || !made {
		t.Fatal("actor scope collided", err)
	}
}

func TestPostgresTwoClaimersAndSkipLocked(t *testing.T) {
	p := dbtest.New(t)
	s := New(p)
	ctx := context.Background()
	enqueue(t, s, "one")
	start := make(chan struct{})
	var wg sync.WaitGroup
	out := make(chan *Job, 2)
	errs := make(chan error, 2)
	for _, worker := range []string{"first", "second"} {
		wg.Add(1)
		go func(w string) { defer wg.Done(); <-start; j, e := s.Claim(ctx, w); out <- j; errs <- e }(worker)
	}
	close(start)
	wg.Wait()
	close(out)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	claimed := 0
	for j := range out {
		if j != nil {
			claimed++
			if j.Attempts != 1 {
				t.Fatal("attempt duplicated")
			}
		}
	}
	if claimed != 1 {
		t.Fatal("same job claimed twice", claimed)
	}
	locked := enqueue(t, s, "locked")
	free := enqueue(t, s, "free")
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT id FROM jobs WHERE id=$1 FOR UPDATE`, locked.ID); err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	j, err := s.Claim(deadline, "third")
	if err != nil || j == nil || j.ID != free.ID {
		t.Fatal("claim blocked on locked row", err)
	}
}

func TestPostgresExpiryFencingRenewAndReclaim(t *testing.T) {
	p := dbtest.New(t)
	s := New(p)
	s.LeaseDuration = 30 * time.Millisecond
	ctx := context.Background()
	enqueue(t, s, "expiry")
	old := claim(t, s, "old")
	if _, err := p.Exec(ctx, `SELECT pg_sleep(0.06)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, old.ID, old.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("expired worker completed before reclaim", err)
	}
	if err := s.Renew(ctx, old.ID, old.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("expired worker renewed", err)
	}
	s.LeaseDuration = time.Second
	fresh := claim(t, s, "fresh")
	if fresh.ID != old.ID || fresh.LeaseToken == old.LeaseToken || fresh.Attempts != 2 {
		t.Fatal("claim not fenced")
	}
	for _, err := range []error{s.Complete(ctx, old.ID, old.LeaseToken), s.Renew(ctx, old.ID, old.LeaseToken), s.Fail(ctx, old.ID, old.LeaseToken, "worker_error")} {
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatal("stale mutation accepted", err)
		}
	}
	if err := s.Renew(ctx, fresh.ID, fresh.LeaseToken); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, fresh.ID, fresh.LeaseToken); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, fresh.ID, fresh.LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("duplicate ACK changed terminal job", err)
	}
	if count(t, p, `SELECT count(*) FROM system_check_results WHERE job_id=$1`, fresh.ID) != 1 || count(t, p, `SELECT count(*) FROM audit_events WHERE target_id=$1 AND action='job.succeeded'`, fresh.ID) != 1 {
		t.Fatal("duplicate effect/audit")
	}
}

func TestPostgresRetryAndAbandonedLastAttemptBecomeFailed(t *testing.T) {
	p := dbtest.New(t)
	s := New(p)
	s.RetryDelay = 0
	ctx := context.Background()
	j := enqueue(t, s, "retry")
	for attempt := 1; attempt <= 3; attempt++ {
		claimed := claim(t, s, "worker")
		if claimed.Attempts != attempt {
			t.Fatal("wrong attempt")
		}
		if err := s.Fail(ctx, j.ID, claimed.LeaseToken, "worker_error"); err != nil {
			t.Fatal(err)
		}
	}
	failed, err := s.Get(ctx, j.ID)
	if err != nil || failed.Status != "failed" || failed.ErrorCode != "worker_error" || failed.FinishedAt == nil {
		t.Fatal("not terminal after max attempts", err)
	}
	if next, err := s.Claim(ctx, "worker"); err != nil || next != nil {
		t.Fatal("exhausted job reclaimed", err)
	}
	crash := enqueue(t, s, "crash-last")
	if _, err = p.Exec(ctx, `UPDATE jobs SET max_attempts=1 WHERE id=$1`, crash.ID); err != nil {
		t.Fatal(err)
	}
	s.LeaseDuration = 30 * time.Millisecond
	old := claim(t, s, "crashed")
	if _, err = p.Exec(ctx, `SELECT pg_sleep(0.06)`); err != nil {
		t.Fatal(err)
	}
	if next, err := s.Claim(ctx, "replacement"); err != nil || next != nil {
		t.Fatal("abandoned final attempt reclaimed", err)
	}
	failed, err = s.Get(ctx, old.ID)
	if err != nil || failed.Status != "failed" || failed.ErrorCode != "lease_expired" {
		t.Fatal("abandoned job stranded", err)
	}
	if count(t, p, `SELECT count(*) FROM audit_events WHERE target_id=$1 AND action='job.failed'`, old.ID) != 1 {
		t.Fatal("dead attempt missing audit")
	}
}

func TestPostgresPoolRestartAndLocalEffectAtomicRollback(t *testing.T) {
	p := dbtest.New(t)
	s := New(p)
	ctx := context.Background()
	j := enqueue(t, s, "restart")
	cfg := p.Config()
	p.Close()
	replacement, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	s = New(replacement)
	claimed := claim(t, s, "new-process")
	if claimed.ID != j.ID {
		t.Fatal("job did not survive pool restart")
	}
	// Fail the last write to prove effect + terminal state also roll back.
	if _, err = replacement.Exec(ctx, `CREATE FUNCTION reject_success_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.action='job.succeeded' THEN RAISE EXCEPTION 'synthetic_audit_failure'; END IF; RETURN NEW; END; $$;
CREATE TRIGGER reject_success_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_success_audit()`); err != nil {
		t.Fatal(err)
	}
	if err = s.Complete(ctx, j.ID, claimed.LeaseToken); err == nil {
		t.Fatal("injected transaction failure ignored")
	}
	saved, err := s.Get(ctx, j.ID)
	if err != nil || saved.Status != "running" {
		t.Fatal("completion was not rolled back", err)
	}
	if count(t, replacement, `SELECT count(*) FROM system_check_results`) != 0 {
		t.Fatal("effect survived rolled back audit")
	}
	if _, err = replacement.Exec(ctx, `DROP TRIGGER reject_success_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if err = s.Complete(ctx, j.ID, claimed.LeaseToken); err != nil {
		t.Fatal(err)
	}
	if count(t, replacement, `SELECT count(*) FROM system_check_results`) != 1 {
		t.Fatal("local effect absent")
	}
}

func TestPostgresEnqueueRollbackAndHistory(t *testing.T) {
	p := dbtest.New(t)
	s := New(p)
	ctx := context.Background()
	if _, err := p.Exec(ctx, `CREATE FUNCTION reject_enqueue_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'synthetic_audit_failure'; END; $$;
CREATE TRIGGER reject_enqueue_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_enqueue_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enqueue(ctx, "system", "system.check", "rolled-back", json.RawMessage(`{}`)); err == nil {
		t.Fatal("injected audit failure ignored")
	}
	if count(t, p, `SELECT count(*) FROM jobs`) != 0 {
		t.Fatal("enqueue escaped audit rollback")
	}
	if _, err := p.Exec(ctx, `DROP TRIGGER reject_enqueue_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"a", "b", "c"} {
		enqueue(t, s, key)
	}
	first, err := s.List(ctx, 2, "")
	if err != nil || len(first) != 2 {
		t.Fatal(err)
	}
	second, err := s.List(ctx, 2, first[1].ID)
	if err != nil || len(second) != 1 || second[0].ID == first[0].ID {
		t.Fatal("cursor pagination", err)
	}
	if worked, err := s.RunOne(ctx, "worker"); err != nil || !worked {
		t.Fatal("worker", err)
	}
	counts, err := s.Counts(ctx)
	if err != nil || counts["pending"] != 2 || counts["succeeded"] != 1 {
		t.Fatal("wrong overview", counts, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if counts, err = s.Counts(canceled); err == nil || counts != nil {
		t.Fatal("missing telemetry became zero")
	}
}
