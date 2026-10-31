package releases

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// LinkTx is an explicit privileged secret read; ordinary projections never carry
// the token. A lost mutation ACK is recovered through this separate operation.
func (s *Store) LinkTx(ctx context.Context, tx pgx.Tx, actor, user, device string) (string, error) {
	if !database.ValidID(user) || !database.ValidID(device) {
		return "", ErrInvalid
	}
	if _, _, e := s.permitted(ctx, tx, user, device); e != nil {
		return "", e
	}
	var id string
	var cipher []byte
	if e := tx.QueryRow(ctx, "SELECT id::text,token_ciphertext FROM subscriptions WHERE user_id=$1 AND device_id=$2 AND assignment_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid AND assignment_revision IS NOT DISTINCT FROM NULLIF($4::bigint,0) AND token_hash IS NOT NULL FOR SHARE", user, device, s.AssignmentID, s.AssignmentRevision).Scan(&id, &cipher); e != nil {
		return "", ErrUnavailable
	}
	b, e := s.Vault.Open(cipher, "subscription-token:"+id)
	if e != nil {
		return "", e
	}
	defer clear(b)
	if !tokenPattern.Match(b) {
		return "", ErrUnavailable
	}
	if e = audit.Append(ctx, tx, actor, "subscription.link", id, "succeeded"); e != nil {
		return "", e
	}
	return string(b), nil
}

// Delivery checks authorization and token under locks shared with their writers.
// No 304/cache bypass: HEAD follows this same path, including current policy.
func (s *Store) Delivery(ctx context.Context, token string) (compiler.Artifact, error) {
	if !tokenPattern.MatchString(token) || s.Vault == nil {
		return compiler.Artifact{}, ErrDenied
	}
	h := sha256.Sum256([]byte(token))
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return compiler.Artifact{}, e
	}
	defer database.Rollback(tx)
	var user, device, assignment string
	var generation int64
	if e = tx.QueryRow(ctx, "SELECT user_id::text,device_id::text,coalesce(assignment_id::text,''),coalesce(assignment_revision,0) FROM subscriptions WHERE token_hash=$1", h[:]).Scan(&user, &device, &assignment, &generation); e != nil {
		return compiler.Artifact{}, ErrDenied
	}
	scoped := *s
	scoped.AssignmentID, scoped.AssignmentRevision = assignment, generation
	d, credential, e := scoped.permitted(ctx, tx, user, device)
	if e != nil {
		return compiler.Artifact{}, e
	}
	var sub, id, cred string
	var number int64
	var cipher, prov []byte
	e = tx.QueryRow(ctx, `SELECT s.id::text,r.id::text,r.number,r.credential_id::text,r.artifact_ciphertext,r.provenance FROM subscriptions s JOIN subscription_releases r ON r.id=s.active_release WHERE s.token_hash=$1 AND s.user_id=$2 AND s.device_id=$3 FOR SHARE OF s`, h[:], user, device).Scan(&sub, &id, &number, &cred, &cipher, &prov)
	if e != nil {
		return compiler.Artifact{}, ErrDenied
	}
	if cred != credential.ID {
		return compiler.Artifact{}, ErrUnavailable
	}
	var provenance struct {
		GroupID          string     `json:"group_id"`
		SourceValidUntil *time.Time `json:"source_valid_until"`
		SourceExpiresAt  *time.Time `json:"source_expires_at"`
	}
	if json.Unmarshal(prov, &provenance) != nil || provenance.GroupID != d.Entitlement.GroupID {
		return compiler.Artifact{}, ErrUnavailable
	}
	b, e := s.Vault.OpenSource(cipher, "release-artifact:"+sub+":"+id)
	if e != nil {
		return compiler.Artifact{}, e
	}
	defer clear(b)
	now := time.Now().UTC()
	lease := now.Truncate(time.Minute).Add(24 * time.Hour)
	for _, limit := range []*time.Time{&d.Entitlement.ExpiresAt, provenance.SourceValidUntil, provenance.SourceExpiresAt} {
		if limit != nil && limit.Before(lease) {
			lease = *limit
		}
	}
	lease = lease.Truncate(time.Microsecond) // PostgreSQL timestamps retain microseconds.
	if !lease.After(now) {
		return compiler.Artifact{}, ErrUnavailable
	}
	if _, e = tx.Exec(ctx, "INSERT INTO subscription_delivery(subscription_id) VALUES($1) ON CONFLICT DO NOTHING", sub); e != nil {
		return compiler.Artifact{}, e
	}
	var delivered *string
	var previousLease *time.Time
	var wireRevision int64
	if e = tx.QueryRow(ctx, "SELECT release_id::text,revision,valid_until FROM subscription_delivery WHERE subscription_id=$1 FOR UPDATE", sub).Scan(&delivered, &wireRevision, &previousLease); e != nil {
		return compiler.Artifact{}, e
	}
	if delivered != nil && *delivered == id && previousLease != nil && previousLease.After(now.Add(12*time.Hour)) && !previousLease.After(lease) {
		lease = *previousLease
	}
	if delivered == nil || *delivered != id || previousLease == nil || !previousLease.Equal(lease) {
		if wireRevision >= 9007199254740991 {
			return compiler.Artifact{}, ErrCapacity
		}
		wireRevision++
		if _, e = tx.Exec(ctx, "UPDATE subscription_delivery SET release_id=$2,revision=$3,valid_until=$4 WHERE subscription_id=$1", sub, id, wireRevision, lease); e != nil {
			return compiler.Artifact{}, e
		}
	}
	var metadata struct {
		Subscription struct {
			Title string `json:"title"`
		} `json:"subscription"`
	}
	if json.Unmarshal(b, &metadata) != nil {
		return compiler.Artifact{}, ErrUnavailable
	}
	_ = number // release history and wire revisions intentionally have separate clocks.
	result, e := compiler.Build(compiler.Input{ID: sub, Revision: wireRevision, Title: metadata.Subscription.Title, Now: now, ExpiresAt: d.Entitlement.ExpiresAt, LeaseUntil: lease, MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}, Source: &compiler.Source{Format: "manifest", Normalized: b, ValidUntil: provenance.SourceValidUntil, ExpiresAt: provenance.SourceExpiresAt}})
	if e != nil {
		return compiler.Artifact{}, ErrUnavailable
	}
	if e = tx.Commit(ctx); e != nil {
		clear(result.Body)
		return compiler.Artifact{}, e
	}
	return result, nil
}
