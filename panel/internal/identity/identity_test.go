package identity

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/jobs"
)

const testPassword = "test-only-long-password-123"

func bootstrapOwner(t *testing.T, s *Store) (Admin, Session) {
	t.Helper()
	ctx := context.Background()
	token, _ := RandomToken()
	if err := PrepareBootstrap(ctx, s.Pool, TokenHash(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	a, err := s.Bootstrap(ctx, token, "owner", testPassword, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.Login(ctx, "owner", testPassword, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return a, session
}

func TestPasswordAndTokenBounds(t *testing.T) {
	hash, err := hashPassword(testPassword)
	if err != nil || !verifyPassword(testPassword, hash) || verifyPassword("wrong", hash) {
		t.Fatal("password roundtrip")
	}
	for _, password := range []string{"short", strings.Repeat("a", 129)} {
		if _, err := hashPassword(password); !errors.Is(err, ErrInvalid) {
			t.Fatal("password bounds")
		}
	}
	for _, bad := range []string{strings.Replace(hash, "m=65536", "m=4294967295", 1), strings.Replace(hash, "t=3", "t=100", 1), strings.Replace(hash, "p=1", "p=255", 1), strings.Repeat("x", 1024)} {
		if verifyPassword(testPassword, bad) {
			t.Fatal("unsafe PHC accepted")
		}
	}
	one, _ := RandomToken()
	two, _ := RandomToken()
	if !tokenValid(one) || one == two || len(TokenHash(one)) != 32 || CSRFToken(one) == one || CSRFToken(one) == CSRFToken(two) {
		t.Fatal("random token or CSRF isolation")
	}
	if CSRFToken(one) != CSRFToken(one) || CheckCSRF(Session{CSRFToken: CSRFToken(one)}, CSRFToken(two)) != ErrCSRF {
		t.Fatal("CSRF stability/check")
	}
}

func TestBootstrapOneTimeConcurrentAndHashOnly(t *testing.T) {
	p := dbtest.New(t)
	s := New(p, time.Hour)
	ctx := context.Background()
	token, _ := RandomToken()
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	if err := PrepareBootstrap(ctx, p, TokenHash(token), expires); err != nil {
		t.Fatal(err)
	}
	if err := PrepareBootstrap(ctx, p, TokenHash(token), expires); err != nil {
		t.Fatal("same-token prepare retry", err)
	}
	other, _ := RandomToken()
	if err := PrepareBootstrap(ctx, p, TokenHash(other), expires); err != ErrConflict {
		t.Fatal("active token replacement", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"first", "second"} {
		go func(name string) {
			<-start
			_, err := s.Bootstrap(ctx, token, name, testPassword, "127.0.0.1")
			results <- err
		}(name)
	}
	close(start)
	one, two := <-results, <-results
	if !((one == nil && two == ErrSetup) || (two == nil && one == ErrSetup)) {
		t.Fatalf("bootstrap race: %v / %v", one, two)
	}
	var count int
	var consumed bool
	if err := p.QueryRow(ctx, "SELECT count(*) FROM admins WHERE role='owner'").Scan(&count); err != nil || count != 1 {
		t.Fatal("owner count", count, err)
	}
	if err := p.QueryRow(ctx, "SELECT bootstrap_hash IS NULL AND bootstrap_consumed_at IS NOT NULL FROM identity_control").Scan(&consumed); err != nil || !consumed {
		t.Fatal("bootstrap not consumed")
	}
	if err := PrepareBootstrap(ctx, p, TokenHash(other), expires); err != ErrSetup {
		t.Fatal("rearm after owner", err)
	}
	rows, _ := p.Query(ctx, "SELECT password_hash FROM admins")
	defer rows.Close()
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil || strings.Contains(encoded, testPassword) || !strings.HasPrefix(encoded, "$argon2id$") {
			t.Fatal("plaintext/password format")
		}
	}
}

func TestExpiredBootstrapAndUnarmedFailClosed(t *testing.T) {
	p := dbtest.New(t)
	s := New(p, time.Hour)
	ctx := context.Background()
	token, _ := RandomToken()
	if _, err := s.Bootstrap(ctx, token, "owner", testPassword, "local"); err != ErrSetup {
		t.Fatal("unarmed", err)
	}
	if err := PrepareBootstrap(ctx, p, TokenHash(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, "UPDATE identity_control SET bootstrap_expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bootstrap(ctx, token, "owner", testPassword, "local"); err != ErrSetup {
		t.Fatal("expired", err)
	}
}

func TestSessionsRolesRevisionAndLastOwnerRace(t *testing.T) {
	p := dbtest.New(t)
	s := New(p, time.Hour)
	ctx := context.Background()
	owner, session := bootstrapOwner(t, s)
	second, err := s.CreateAdmin(ctx, session.Token, "second", testPassword, Owner)
	if err != nil {
		t.Fatal(err)
	}
	secondSession, err := s.Login(ctx, "second", testPassword, "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	var storedToken, storedCSRF []byte
	if err = p.QueryRow(ctx, "SELECT token_hash,csrf_hash FROM admin_sessions WHERE admin_id=$1", owner.ID).Scan(&storedToken, &storedCSRF); err != nil || !bytes.Equal(storedToken, TokenHash(session.Token)) || !bytes.Equal(storedCSRF, TokenHash(session.CSRFToken)) {
		t.Fatal("session hash persistence", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	role := Support
	for _, pair := range []Session{session, secondSession} {
		go func(pair Session) {
			<-start
			_, err := s.UpdateAdmin(ctx, pair.Token, pair.User.ID, 1, &role, nil)
			results <- err
		}(pair)
	}
	close(start)
	one, two := <-results, <-results
	if !((one == nil && two == ErrLastOwner) || (two == nil && one == ErrLastOwner)) {
		t.Fatalf("last-owner race %v / %v", one, two)
	}
	var activeOwners int
	if err = p.QueryRow(ctx, "SELECT count(*) FROM admins WHERE role='owner' AND NOT disabled").Scan(&activeOwners); err != nil || activeOwners != 1 {
		t.Fatal("lost final owner")
	}
	ownerSession, demoted := session, second
	if _, err := s.Authenticate(ctx, session.Token); err == ErrUnauthorized {
		ownerSession, demoted = secondSession, owner
	}
	if _, err := s.UpdateAdmin(ctx, ownerSession.Token, demoted.ID, 1, &role, nil); err != ErrRevision {
		t.Fatal("revision CAS", err)
	}
	disabled := true
	updated, err := s.UpdateAdmin(ctx, ownerSession.Token, demoted.ID, 2, nil, &disabled)
	if err != nil || !updated.Disabled || updated.Revision != 3 {
		t.Fatal("disable", err)
	}
	if _, err := s.Login(ctx, demoted.Username, testPassword, "local"); err != ErrCredentials {
		t.Fatal("disabled login", err)
	}
	var failedLogins int
	if err := p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='identity.login_failed' AND actor_id='anonymous'").Scan(&failedLogins); err != nil || failedLogins != 1 {
		t.Fatal("disabled login omitted safe failure audit", failedLogins, err)
	}
	other, err := s.Login(ctx, ownerSession.User.Username, testPassword, "local")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(ctx, ownerSession.Token, true); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{ownerSession.Token, other.Token} {
		if _, err := s.Authenticate(ctx, raw); err != ErrUnauthorized {
			t.Fatal("revoke all", err)
		}
	}
}

func TestExpiryRatePersistenceAndNoPlaintextAudit(t *testing.T) {
	p := dbtest.New(t)
	s := New(p, time.Hour)
	ctx := context.Background()
	_, session := bootstrapOwner(t, s)
	if _, err := p.Exec(ctx, "UPDATE admin_sessions SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, session.Token); err != ErrUnauthorized {
		t.Fatal("expired session", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed, limited := 0, 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := New(p, time.Hour).limit(ctx, map[string]int{"synthetic:account": 3})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				passed++
			} else if err == ErrRateLimited {
				limited++
			} else {
				t.Errorf("limiter: %v", err)
			}
		}()
	}
	wg.Wait()
	if passed != 3 || limited != 5 {
		t.Fatal("persistent concurrent limiter", passed, limited)
	}
	if err := New(p, time.Hour).limit(ctx, map[string]int{"synthetic:account": 3}); err != ErrRateLimited {
		t.Fatal("restart bypassed limiter")
	}
	if _, err := s.Login(ctx, "absent-sensitive-name", "sensitive-wrong-password", "192.0.2.12"); err != ErrCredentials {
		t.Fatal(err)
	}
	var text string
	if err := p.QueryRow(ctx, "SELECT coalesce(json_agg(audit_events)::text,'') FROM audit_events").Scan(&text); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{session.Token, session.CSRFToken, testPassword, "absent-sensitive-name", "sensitive-wrong-password", "192.0.2.12"} {
		if strings.Contains(text, forbidden) {
			t.Fatal("sensitive data in audit")
		}
	}
}

func TestAuthorizedEnqueueOrdersAgainstDemotion(t *testing.T) {
	p := dbtest.New(t)
	s := New(p, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, owner := bootstrapOwner(t, s)
	infra, err := s.CreateAdmin(ctx, owner.Token, "infra", testPassword, InfrastructureOperator)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := s.Login(ctx, infra.Username, testPassword, "local")
	if err != nil {
		t.Fatal(err)
	}
	queue := jobs.New(p)
	authorized, release := make(chan struct{}), make(chan struct{})
	enqueued := make(chan error, 1)
	go func() {
		enqueued <- s.WithAuthorizedSession(ctx, actor.Token, []Role{Owner, InfrastructureOperator}, func(tx pgx.Tx, fresh Session) error {
			close(authorized)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			_, _, err := queue.EnqueueTx(ctx, tx, fresh.User.ID, "system.check", "before-demotion", []byte(`{}`))
			return err
		})
	}()
	select {
	case <-authorized:
	case <-ctx.Done():
		t.Fatal("authorization lock not reached")
	}
	demoted := make(chan error, 1)
	go func() {
		role := Support
		_, err := s.UpdateAdmin(ctx, owner.Token, actor.User.ID, actor.User.Revision, &role, nil)
		demoted <- err
	}()
	// The real PostgreSQL role mutation must wait for the authorized job commit.
	select {
	case err := <-demoted:
		close(release)
		t.Fatalf("demotion bypassed authorization transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-enqueued; err != nil {
		t.Fatal(err)
	}
	if err := <-demoted; err != nil {
		t.Fatal(err)
	}
	err = s.WithAuthorizedSession(ctx, actor.Token, []Role{Owner, InfrastructureOperator}, func(tx pgx.Tx, fresh Session) error {
		_, _, err := queue.EnqueueTx(ctx, tx, fresh.User.ID, "system.check", "after-demotion", []byte(`{}`))
		return err
	})
	if err != ErrUnauthorized {
		t.Fatal("stale middleware principal could enqueue", err)
	}
	var jobCount, auditCount int
	if err = p.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if err = p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='job.enqueued'").Scan(&auditCount); err != nil || jobCount != 1 || auditCount != 1 {
		t.Fatal("authorized transaction/audit counts", jobCount, auditCount, err)
	}
}
