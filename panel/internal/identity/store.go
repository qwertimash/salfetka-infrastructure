package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
)

type Store struct {
	Pool *pgxpool.Pool
	ttl  time.Duration
	work chan struct{}
}

func New(pool *pgxpool.Pool, ttl time.Duration) *Store {
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 8 * time.Hour
	}
	return &Store{Pool: pool, ttl: ttl, work: make(chan struct{}, 4)}
}

func safeDB(err error) error {
	if err == nil {
		return nil
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		return ErrConflict
	}
	return ErrUnavailable
}

func gate(ctx context.Context, tx pgx.Tx) error {
	var singleton bool
	return tx.QueryRow(ctx, "SELECT singleton FROM identity_control WHERE singleton = true FOR UPDATE").Scan(&singleton)
}

// PrepareBootstrap is a local CLI operation. It cannot re-arm consumed setup or
// replace an active token. Identical retry is idempotent, including after ACK loss.
func PrepareBootstrap(ctx context.Context, pool *pgxpool.Pool, hash []byte, expires time.Time) error {
	if len(hash) != 32 {
		return ErrInvalid
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return safeDB(err)
	}
	defer database.Rollback(tx)
	if err = gate(ctx, tx); err != nil {
		return safeDB(err)
	}
	var oldHash []byte
	var oldExpires, consumed *time.Time
	var now time.Time
	var hasAdmin bool
	err = tx.QueryRow(ctx, `SELECT bootstrap_hash, bootstrap_expires_at, bootstrap_consumed_at,
clock_timestamp(), EXISTS(SELECT 1 FROM admins) FROM identity_control WHERE singleton`).Scan(&oldHash, &oldExpires, &consumed, &now, &hasAdmin)
	if err != nil {
		return safeDB(err)
	}
	if hasAdmin || consumed != nil {
		return ErrSetup
	}
	if !expires.After(now) || expires.After(now.Add(24*time.Hour)) {
		return ErrInvalid
	}
	if oldExpires != nil && oldExpires.After(now) {
		if subtle.ConstantTimeCompare(oldHash, hash) == 1 && oldExpires.Equal(expires.UTC().Truncate(time.Microsecond)) {
			return safeDB(tx.Commit(ctx))
		}
		return ErrConflict
	}
	_, err = tx.Exec(ctx, `UPDATE identity_control SET bootstrap_hash=$1,bootstrap_expires_at=$2 WHERE singleton`, hash, expires)
	if err == nil {
		err = audit.Append(ctx, tx, "system", "identity.bootstrap_prepared", "", "accepted")
	}
	if err != nil {
		return safeDB(err)
	}
	return safeDB(tx.Commit(ctx))
}

func (s *Store) SetupRequired(ctx context.Context) (bool, error) {
	var required bool
	err := s.Pool.QueryRow(ctx, "SELECT NOT EXISTS(SELECT 1 FROM admins)").Scan(&required)
	return required, safeDB(err)
}

// Fixed windows are persisted across API restarts. Both account and direct peer
// IP buckets apply; forwarded headers never select an IP here or in HTTP.
func (s *Store) limit(ctx context.Context, values map[string]int) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return safeDB(err)
	}
	defer database.Rollback(tx)
	denied := false
	for _, key := range keys {
		var attempts int
		err = tx.QueryRow(ctx, `INSERT INTO identity_rate_limits(bucket_hash,attempts) VALUES($1,1)
ON CONFLICT(bucket_hash) DO UPDATE SET
attempts=CASE WHEN identity_rate_limits.window_started_at <= clock_timestamp()-interval '15 minutes' THEN 1 ELSE least(identity_rate_limits.attempts+1,1000000) END,
window_started_at=CASE WHEN identity_rate_limits.window_started_at <= clock_timestamp()-interval '15 minutes' THEN clock_timestamp() ELSE identity_rate_limits.window_started_at END
RETURNING attempts`, TokenHash(key)).Scan(&attempts)
		if err != nil {
			return safeDB(err)
		}
		denied = denied || attempts > values[key]
	}
	if _, err = tx.Exec(ctx, "DELETE FROM identity_rate_limits WHERE window_started_at < clock_timestamp()-interval '1 day'"); err != nil {
		return safeDB(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return safeDB(err)
	}
	if denied {
		return ErrRateLimited
	}
	return nil
}

func (s *Store) password(ctx context.Context, password string) (string, error) {
	select {
	case s.work <- struct{}{}:
		defer func() { <-s.work }()
	case <-ctx.Done():
		return "", ErrUnavailable
	}
	return hashPassword(password)
}

func (s *Store) Bootstrap(ctx context.Context, token, username, password, ip string) (Admin, error) {
	var empty Admin
	if err := s.limit(ctx, map[string]int{"setup:ip:" + ip: 20}); err != nil {
		return empty, err
	}
	name, err := NormalizeUsername(username)
	if err != nil || !tokenValid(token) {
		return empty, ErrInvalid
	}
	var valid bool
	err = s.Pool.QueryRow(ctx, `SELECT COALESCE(bootstrap_hash=$1 AND bootstrap_expires_at>clock_timestamp()
AND bootstrap_consumed_at IS NULL AND NOT EXISTS(SELECT 1 FROM admins),false) FROM identity_control WHERE singleton`, TokenHash(token)).Scan(&valid)
	if err != nil {
		return empty, safeDB(err)
	}
	if !valid {
		return empty, ErrSetup
	}
	hash, err := s.password(ctx, password)
	if err != nil {
		return empty, err
	}
	id, err := newID()
	if err != nil {
		return empty, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return empty, safeDB(err)
	}
	defer database.Rollback(tx)
	if err = gate(ctx, tx); err != nil {
		return empty, safeDB(err)
	}
	var ok bool
	err = tx.QueryRow(ctx, `SELECT COALESCE(bootstrap_hash=$1 AND bootstrap_expires_at>clock_timestamp()
AND bootstrap_consumed_at IS NULL AND NOT EXISTS(SELECT 1 FROM admins), false) FROM identity_control WHERE singleton`, TokenHash(token)).Scan(&ok)
	if err != nil {
		return empty, safeDB(err)
	}
	if !ok {
		return empty, ErrSetup
	}
	a, err := insertAdmin(ctx, tx, id, name, hash, Owner)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE identity_control SET bootstrap_hash=NULL,bootstrap_expires_at=NULL,bootstrap_consumed_at=clock_timestamp() WHERE singleton`)
	}
	if err == nil {
		err = audit.Append(ctx, tx, a.ID, "identity.bootstrap_completed", a.ID, "succeeded")
	}
	if err != nil {
		return empty, safeDB(err)
	}
	return a, safeDB(tx.Commit(ctx))
}

const adminColumns = "id::text,username,role,disabled,revision,created_at,updated_at"

type scanner interface{ Scan(...any) error }

func scanAdmin(row scanner) (Admin, error) {
	var a Admin
	err := row.Scan(&a.ID, &a.Username, &a.Role, &a.Disabled, &a.Revision, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func insertAdmin(ctx context.Context, tx pgx.Tx, id, name, hash string, role Role) (Admin, error) {
	return scanAdmin(tx.QueryRow(ctx, "INSERT INTO admins(id,username,password_hash,role) VALUES($1,$2,$3,$4) RETURNING "+adminColumns, id, name, hash, role))
}

func (s *Store) Login(ctx context.Context, username, password, ip string) (Session, error) {
	var empty Session
	name, nameErr := NormalizeUsername(username)
	if nameErr != nil {
		name = "invalid"
	}
	if err := s.limit(ctx, map[string]int{"login:ip:" + ip: 50, "login:account:" + name: 10}); err != nil {
		return empty, err
	}
	if len(password) > 128 {
		return empty, ErrCredentials
	}
	var id, hash string
	err := s.Pool.QueryRow(ctx, "SELECT id::text,password_hash FROM admins WHERE username=$1", name).Scan(&id, &hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return empty, safeDB(err)
	}
	select {
	case s.work <- struct{}{}:
	case <-ctx.Done():
		return empty, ErrUnavailable
	}
	valid := false
	if err == nil && nameErr == nil {
		valid = verifyPassword(password, hash)
	} else {
		dummyPasswordCheck(password)
	}
	<-s.work
	if !valid {
		return empty, s.failedLogin(ctx)
	}
	token, err := RandomToken()
	if err != nil {
		return empty, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return empty, safeDB(err)
	}
	defer database.Rollback(tx)
	a, err := scanAdmin(tx.QueryRow(ctx, "SELECT "+adminColumns+" FROM admins WHERE id=$1 AND password_hash=$2 FOR UPDATE", id, hash))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && a.Disabled) {
		if err := audit.Append(ctx, tx, "anonymous", "identity.login_failed", "", "failed"); err != nil {
			return empty, safeDB(err)
		}
		if err := tx.Commit(ctx); err != nil {
			return empty, safeDB(err)
		}
		return empty, ErrCredentials
	}
	if err != nil {
		return empty, safeDB(err)
	}
	csrf := CSRFToken(token)
	var expires time.Time
	err = tx.QueryRow(ctx, `INSERT INTO admin_sessions(token_hash,csrf_hash,admin_id,admin_revision,expires_at)
VALUES($1,$2,$3,$4,clock_timestamp()+($5 * interval '1 second')) RETURNING expires_at`, TokenHash(token), TokenHash(csrf), a.ID, a.Revision, int64(s.ttl/time.Second)).Scan(&expires)
	if err == nil {
		_, err = tx.Exec(ctx, "DELETE FROM admin_sessions WHERE expires_at<=clock_timestamp()")
	}
	if err == nil {
		err = audit.Append(ctx, tx, a.ID, "identity.login_succeeded", a.ID, "succeeded")
	}
	if err != nil {
		return empty, safeDB(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, safeDB(err)
	}
	return Session{User: a, Token: token, CSRFToken: csrf, ExpiresAt: expires}, nil
}

func (s *Store) failedLogin(ctx context.Context) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return safeDB(err)
	}
	defer database.Rollback(tx)
	if err = audit.Append(ctx, tx, "anonymous", "identity.login_failed", "", "failed"); err != nil {
		return safeDB(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return safeDB(err)
	}
	return ErrCredentials
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func authenticate(ctx context.Context, q queryer, token, locking string) (Session, error) {
	var s Session
	if !tokenValid(token) {
		return s, ErrUnauthorized
	}
	if locking != "" {
		// All writers take the admin row before any session row. A joined FOR
		// UPDATE/SHARE can acquire row locks in planner order and deadlock against
		// revoke (admin -> sessions). Re-read the session after taking this lock.
		var adminID, lockedID string
		err := q.QueryRow(ctx, "SELECT admin_id::text FROM admin_sessions WHERE token_hash=$1 AND expires_at>clock_timestamp()", TokenHash(token)).Scan(&adminID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s, ErrUnauthorized
		}
		if err != nil {
			return s, safeDB(err)
		}
		adminLock := "FOR SHARE"
		if locking == "FOR UPDATE OF a" {
			adminLock = "FOR UPDATE"
		}
		err = q.QueryRow(ctx, "SELECT id::text FROM admins WHERE id=$1 "+adminLock, adminID).Scan(&lockedID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s, ErrUnauthorized
		}
		if err != nil {
			return s, safeDB(err)
		}
		locking = "FOR SHARE OF s"
	}
	var csrfHash []byte
	err := q.QueryRow(ctx, `SELECT a.id::text,a.username,a.role,a.disabled,a.revision,a.created_at,a.updated_at,s.expires_at,s.csrf_hash
FROM admin_sessions s JOIN admins a ON a.id=s.admin_id
WHERE s.token_hash=$1 AND s.expires_at>clock_timestamp() AND NOT a.disabled AND a.revision=s.admin_revision `+locking, TokenHash(token)).Scan(
		&s.User.ID, &s.User.Username, &s.User.Role, &s.User.Disabled, &s.User.Revision, &s.User.CreatedAt, &s.User.UpdatedAt, &s.ExpiresAt, &csrfHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrUnauthorized
	}
	if err != nil {
		return s, safeDB(err)
	}
	s.Token, s.CSRFToken = token, CSRFToken(token)
	if subtle.ConstantTimeCompare(csrfHash, TokenHash(s.CSRFToken)) != 1 {
		return Session{}, ErrUnauthorized
	}
	return s, nil
}

func (s *Store) Authenticate(ctx context.Context, token string) (Session, error) {
	return authenticate(ctx, s.Pool, token, "")
}

// WithAuthorizedSession orders a protected DB mutation against logout, disable,
// role change and session revocation. Authorization, effect and audit share one
// transaction; the callback must not commit, open a nested transaction or do I/O.
func (s *Store) WithAuthorizedSession(ctx context.Context, token string, allowed []Role, fn func(pgx.Tx, Session) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return safeDB(err)
	}
	defer database.Rollback(tx)
	session, err := authenticate(ctx, tx, token, "FOR SHARE OF a,s")
	if err != nil {
		return err
	}
	permitted := false
	for _, role := range allowed {
		permitted = permitted || session.User.Role == role
	}
	if !permitted {
		return ErrForbidden
	}
	if err := fn(tx, session); err != nil {
		return err
	}
	return safeDB(tx.Commit(ctx))
}

func CheckCSRF(session Session, supplied string) error {
	if len(supplied) != 43 || subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(supplied)) != 1 {
		return ErrCSRF
	}
	return nil
}

func (s *Store) Logout(ctx context.Context, token string, all bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return safeDB(err)
	}
	defer database.Rollback(tx)
	actor, err := authenticate(ctx, tx, token, "FOR UPDATE OF a")
	if err != nil {
		return err
	}
	action := "identity.logout"
	if all {
		action = "identity.sessions_revoked"
		_, err = tx.Exec(ctx, "DELETE FROM admin_sessions WHERE admin_id=$1", actor.User.ID)
	} else {
		_, err = tx.Exec(ctx, "DELETE FROM admin_sessions WHERE token_hash=$1", TokenHash(token))
	}
	if err == nil {
		err = audit.Append(ctx, tx, actor.User.ID, action, actor.User.ID, "succeeded")
	}
	if err != nil {
		return safeDB(err)
	}
	return safeDB(tx.Commit(ctx))
}

func ownerTx(ctx context.Context, tx pgx.Tx, token string) (Session, error) {
	if err := gate(ctx, tx); err != nil {
		return Session{}, safeDB(err)
	}
	actor, err := authenticate(ctx, tx, token, "FOR SHARE OF a,s")
	if err != nil {
		return actor, err
	}
	if actor.User.Role != Owner {
		return actor, ErrForbidden
	}
	return actor, nil
}

func (s *Store) CreateAdmin(ctx context.Context, token, username, password string, role Role) (Admin, error) {
	var empty Admin
	name, err := NormalizeUsername(username)
	if err != nil || !role.Valid() {
		return empty, ErrInvalid
	}
	hash, err := s.password(ctx, password)
	if err != nil {
		return empty, err
	}
	id, err := newID()
	if err != nil {
		return empty, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return empty, safeDB(err)
	}
	defer database.Rollback(tx)
	actor, err := ownerTx(ctx, tx, token)
	if err != nil {
		return empty, err
	}
	a, err := insertAdmin(ctx, tx, id, name, hash, role)
	if err == nil {
		err = audit.Append(ctx, tx, actor.User.ID, "identity.admin_created", a.ID, "succeeded")
	}
	if err != nil {
		return empty, safeDB(err)
	}
	return a, safeDB(tx.Commit(ctx))
}

func (s *Store) ListAdmins(ctx context.Context) ([]Admin, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+adminColumns+" FROM admins ORDER BY created_at,id LIMIT 1000")
	if err != nil {
		return nil, safeDB(err)
	}
	defer rows.Close()
	items := make([]Admin, 0)
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, safeDB(err)
		}
		items = append(items, a)
	}
	return items, safeDB(rows.Err())
}

func (s *Store) UpdateAdmin(ctx context.Context, token, id string, revision int64, role *Role, disabled *bool) (Admin, error) {
	var empty Admin
	if !ValidID(id) || revision < 1 || (role == nil && disabled == nil) || (role != nil && !role.Valid()) {
		return empty, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return empty, safeDB(err)
	}
	defer database.Rollback(tx)
	actor, err := ownerTx(ctx, tx, token)
	if err != nil {
		return empty, err
	}
	a, err := scanAdmin(tx.QueryRow(ctx, "SELECT "+adminColumns+" FROM admins WHERE id=$1 FOR UPDATE", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, ErrNotFound
	}
	if err != nil {
		return empty, safeDB(err)
	}
	if a.Revision != revision {
		return empty, ErrRevision
	}
	oldOwner := a.Role == Owner && !a.Disabled
	if role != nil {
		a.Role = *role
	}
	if disabled != nil {
		a.Disabled = *disabled
	}
	if oldOwner && (a.Role != Owner || a.Disabled) {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM admins WHERE role='owner' AND NOT disabled").Scan(&count); err != nil {
			return empty, safeDB(err)
		}
		if count <= 1 {
			return empty, ErrLastOwner
		}
	}
	a, err = scanAdmin(tx.QueryRow(ctx, "UPDATE admins SET role=$2,disabled=$3,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING "+adminColumns, id, a.Role, a.Disabled))
	if err == nil {
		_, err = tx.Exec(ctx, "DELETE FROM admin_sessions WHERE admin_id=$1", id)
	}
	if err == nil {
		err = audit.Append(ctx, tx, actor.User.ID, "identity.admin_updated", id, "succeeded")
	}
	if err != nil {
		return empty, safeDB(err)
	}
	return a, safeDB(tx.Commit(ctx))
}
