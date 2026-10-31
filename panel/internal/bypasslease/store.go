package bypasslease

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
)

type Store struct {
	Pool      *pgxpool.Pool
	authorize func(context.Context, pgx.Tx, Owner) error
}

// Authenticated binds one request's verified node identity to every transaction,
// including revocation checks under the same locks as the state mutation.
func Authenticated(pool *pgxpool.Pool, authorize func(context.Context, pgx.Tx, Owner) error) *Store {
	if authorize == nil {
		panic("bypass authorization required")
	}
	return &Store{Pool: pool, authorize: authorize}
}

func (s *Store) node(ctx context.Context, tx pgx.Tx, o Owner) error {
	if s.authorize != nil {
		if err := s.authorize(ctx, tx, o); err != nil {
			return err
		}
	}
	return node(ctx, tx, o)
}

// node locks match the existing node->installation->user order. An existing
// mTLS boundary must supply Owner; these row checks are NOT mTLS authentication.
func node(ctx context.Context, tx pgx.Tx, o Owner) error {
	if !o.valid() {
		return ErrInvalid
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM nodes_registry WHERE id=$1 FOR SHARE`, o.NodeID).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDenied
		}
		return err
	}
	if state != "active" {
		return ErrDenied
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(enabled AND installation_id=$2 AND engine_epoch=$3 AND endpoint->>'backend'='olcrtc',false) FROM nodes_vpn_installations WHERE node_id=$1 FOR SHARE`, o.NodeID, o.InstallationID, o.EngineEpoch).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	if !allowed {
		return ErrDenied
	}
	return nil
}

func lockUser(ctx context.Context, tx pgx.Tx, user string) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM access_users WHERE id=$1 FOR UPDATE`, user).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDenied
	}
	return err
}

// Uses the same access decision implementation as ordinary policy issuance.
func eligible(ctx context.Context, tx pgx.Tx, o Owner, user string) (string, time.Time, error) {
	d, err := access.New(nil, nil).DetailTx(ctx, tx, user)
	if err != nil {
		return "", time.Time{}, err
	}
	if !d.Decision.Allowed || d.Entitlement == nil {
		return "", time.Time{}, ErrDenied
	}
	var group string
	if err = tx.QueryRow(ctx, `SELECT group_id::text FROM nodes_vpn_installations WHERE node_id=$1`, o.NodeID).Scan(&group); err != nil {
		return "", time.Time{}, err
	}
	if d.Entitlement.GroupID != group {
		return "", time.Time{}, ErrDenied
	}
	for _, device := range d.Devices {
		if device.Credential != nil && device.Credential.ID == o.CredentialID && device.Decision.Allowed {
			return device.ID, d.Entitlement.ExpiresAt, nil
		}
	}
	return "", time.Time{}, ErrDenied
}

func clock(ctx context.Context, tx pgx.Tx, user string) (time.Time, error) {
	var now, last time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return now, err
	}
	_, err := tx.Exec(ctx, `INSERT INTO bypass_accounts(user_id,clock_watermark) VALUES($1,$2) ON CONFLICT DO NOTHING`, user, now)
	if err != nil {
		return now, err
	}
	if err = tx.QueryRow(ctx, `SELECT clock_watermark FROM bypass_accounts WHERE user_id=$1 FOR UPDATE`, user).Scan(&last); err != nil {
		return now, err
	}
	if now.Before(last) {
		return now, ErrClock
	}
	_, err = tx.Exec(ctx, `UPDATE bypass_accounts SET clock_watermark=$2 WHERE user_id=$1`, user, now)
	return now, err
}

const columns = `user_id::text,generation,node_id::text,installation_id::text,engine_epoch,credential_id::text,device_id::text,request_id::text,state,reason,revision,created_at,expires_at`

func scan(row pgx.Row) (Lease, error) {
	var l Lease
	err := row.Scan(&l.UserID, &l.Generation, &l.NodeID, &l.InstallationID, &l.EngineEpoch, &l.CredentialID, &l.DeviceID, &l.RequestID, &l.State, &l.Reason, &l.Revision, &l.CreatedAt, &l.ExpiresAt)
	return l, err
}
func read(ctx context.Context, tx pgx.Tx, r Ref) (Lease, error) {
	return scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM bypass_leases WHERE user_id=$1 AND generation=$2`, r.UserID, r.Generation))
}

// Preserve the observed clock even on a logical refusal. Otherwise a forward
// clock step, expired response and subsequent rollback could resurrect a lease.
func refuse(ctx context.Context, tx pgx.Tx, reason error) (Lease, error) {
	if err := tx.Commit(ctx); err != nil {
		return Lease{}, err
	}
	return Lease{}, reason
}

// ClaimExplicit records user intent. It never authorizes data or renews a stale
// session. Same request ID returns the CURRENT state of the original lease.
func (s *Store) ClaimExplicit(ctx context.Context, o Owner, requestID string) (Lease, error) {
	if !o.valid() || !database.ValidID(requestID) {
		return Lease{}, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Lease{}, err
	}
	defer database.Rollback(tx)
	if err = s.node(ctx, tx, o); err != nil {
		return Lease{}, err
	}
	var user string
	if err = tx.QueryRow(ctx, `SELECT user_id::text FROM access_credentials WHERE id=$1`, o.CredentialID).Scan(&user); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrDenied
		}
		return Lease{}, err
	}
	if err = lockUser(ctx, tx, user); err != nil {
		return Lease{}, err
	}
	device, _, err := eligible(ctx, tx, o, user)
	if err != nil {
		return Lease{}, err
	}
	now, err := clock(ctx, tx, user)
	if err != nil {
		return Lease{}, err
	}
	old, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM bypass_leases WHERE user_id=$1 AND request_id=$2`, user, requestID))
	if err == nil {
		if old.Owner != o {
			// A restart must still deliver a saved replacement reason to the
			// same credential. This grants no access and never rebinds a lease.
			if old.State == "replaced" && old.NodeID == o.NodeID && old.InstallationID == o.InstallationID && old.CredentialID == o.CredentialID {
				return old, tx.Commit(ctx)
			}
			return Lease{}, ErrConflict
		}
		return old, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Lease{}, err
	}
	var gen int64
	err = tx.QueryRow(ctx, `UPDATE bypass_accounts SET generation=generation+1 WHERE user_id=$1 AND generation<$2 RETURNING generation`, user, MaxSequence).Scan(&gen)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrConflict
	}
	if err != nil {
		return Lease{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE bypass_leases SET state='replaced',reason='session_replaced' WHERE user_id=$1 AND state='pending'`, user); err != nil {
		return Lease{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE bypass_leases SET state='draining',reason='session_replaced' WHERE user_id=$1 AND state='active'`, user); err != nil {
		return Lease{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO bypass_leases(user_id,generation,request_id,device_id,credential_id,node_id,installation_id,engine_epoch,state,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10)`, user, gen, requestID, device, o.CredentialID, o.NodeID, o.InstallationID, o.EngineEpoch, now, now.Add(PrepareTTL))
	if err != nil {
		return Lease{}, err
	}
	out, err := read(ctx, tx, Ref{user, gen})
	if err != nil {
		return Lease{}, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) begin(ctx context.Context, o Owner, r Ref) (pgx.Tx, Lease, error) {
	if !o.valid() || !r.valid() {
		return nil, Lease{}, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, Lease{}, err
	}
	fail := func(e error) (pgx.Tx, Lease, error) { database.Rollback(tx); return nil, Lease{}, e }
	if err = s.node(ctx, tx, o); err != nil {
		return fail(err)
	}
	if err = lockUser(ctx, tx, r.UserID); err != nil {
		return fail(err)
	}
	l, err := read(ctx, tx, r)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrDenied
	}
	if err != nil {
		return fail(err)
	}
	if l.Owner != o {
		return fail(ErrDenied)
	}
	return tx, l, nil
}

// Status allows a revoked device to learn its authenticated terminal reason.
// It does not grant access or extend any deadline.
func (s *Store) Status(ctx context.Context, o Owner, r Ref) (Lease, error) {
	tx, l, err := s.begin(ctx, o, r)
	if err != nil {
		return Lease{}, err
	}
	defer database.Rollback(tx)
	return l, tx.Commit(ctx)
}

func (s *Store) Activate(ctx context.Context, o Owner, r Ref) (Lease, error) {
	tx, l, err := s.begin(ctx, o, r)
	if err != nil {
		return Lease{}, err
	}
	defer database.Rollback(tx)
	_, end, err := eligible(ctx, tx, o, r.UserID)
	if err != nil {
		return Lease{}, err
	}
	now, err := clock(ctx, tx, r.UserID)
	if err != nil {
		return Lease{}, err
	}
	if l.State != "pending" && l.State != "active" {
		return refuse(ctx, tx, ErrStale)
	}
	if !end.After(now) {
		return refuse(ctx, tx, ErrDenied)
	}
	if !l.ExpiresAt.After(now) {
		return refuse(ctx, tx, ErrExpired)
	}
	if l.State == "active" {
		return l, tx.Commit(ctx)
	}
	var blocked bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bypass_leases WHERE user_id=$1 AND state IN('active','draining'))`, r.UserID).Scan(&blocked)
	if err != nil {
		return Lease{}, err
	}
	if blocked {
		return refuse(ctx, tx, ErrPending)
	}
	until := now.Add(LeaseTTL)
	if end.Before(until) {
		until = end
	}
	_, err = tx.Exec(ctx, `UPDATE bypass_leases SET state='active',expires_at=$3 WHERE user_id=$1 AND generation=$2`, r.UserID, r.Generation, until)
	if err != nil {
		return Lease{}, err
	}
	l, err = read(ctx, tx, r)
	if err != nil {
		return Lease{}, err
	}
	return l, tx.Commit(ctx)
}

// Renew CAS and one-step replay do not turn a lost response into a second
// extension. An expired, replaced or closed lease can never be resurrected.
func (s *Store) Renew(ctx context.Context, o Owner, r Ref, expected int64) (Lease, error) {
	if expected < 1 || expected >= MaxSequence {
		return Lease{}, ErrInvalid
	}
	tx, l, err := s.begin(ctx, o, r)
	if err != nil {
		return Lease{}, err
	}
	defer database.Rollback(tx)
	_, end, err := eligible(ctx, tx, o, r.UserID)
	if err != nil {
		return Lease{}, err
	}
	now, err := clock(ctx, tx, r.UserID)
	if err != nil {
		return Lease{}, err
	}
	if l.State != "active" {
		return refuse(ctx, tx, ErrStale)
	}
	if !end.After(now) {
		return refuse(ctx, tx, ErrDenied)
	}
	if !l.ExpiresAt.After(now) {
		return refuse(ctx, tx, ErrExpired)
	}
	if l.Revision == expected+1 {
		return l, tx.Commit(ctx)
	}
	if l.Revision != expected {
		return refuse(ctx, tx, ErrStale)
	}
	until := now.Add(LeaseTTL)
	if end.Before(until) {
		until = end
	}
	_, err = tx.Exec(ctx, `UPDATE bypass_leases SET revision=revision+1,expires_at=$3 WHERE user_id=$1 AND generation=$2`, r.UserID, r.Generation, until)
	if err != nil {
		return Lease{}, err
	}
	l, err = read(ctx, tx, r)
	if err != nil {
		return Lease{}, err
	}
	return l, tx.Commit(ctx)
}

// AcknowledgeClosed may only follow a successful gate drain, not a desired
// policy update, timeout, missing heartbeat or assumption that a node is dead.
// Closing remains permitted after entitlement expiry or a clock regression.
func (s *Store) AcknowledgeClosed(ctx context.Context, o Owner, r Ref) (Lease, error) {
	tx, l, err := s.begin(ctx, o, r)
	if err != nil {
		return Lease{}, err
	}
	defer database.Rollback(tx)
	if l.State == "closed" || l.State == "replaced" {
		return l, tx.Commit(ctx)
	}
	state, reason := "closed", "session_closed"
	if l.State == "draining" {
		state, reason = "replaced", Replaced
	}
	_, err = tx.Exec(ctx, `UPDATE bypass_leases SET state=$3,reason=$4 WHERE user_id=$1 AND generation=$2`, r.UserID, r.Generation, state, reason)
	if err != nil {
		return Lease{}, err
	}
	l, err = read(ctx, tx, r)
	if err != nil {
		return Lease{}, err
	}
	return l, tx.Commit(ctx)
}
