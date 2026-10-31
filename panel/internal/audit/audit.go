// Package audit stores only allowlisted actions and opaque identities. No payload,
// request body, error text, address, username or credential can be appended.
package audit

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
)

var ErrInvalid = errors.New("audit_invalid")
var ErrNotFound = errors.New("audit_cursor_not_found")

var actions = map[string]bool{
	"infrastructure.server_created": true,
	"access.invite_created":         true,
	"subscription_set.publish":      true, "subscription_set.link": true,
	"subscription_set.save": true, "subscription_set.assign": true, "subscription_set.unassign": true,
	"builder.save":       true,
	"subscription.stage": true, "subscription.publish": true, "subscription.check": true, "subscription.rollback": true, "subscription.rotate": true, "subscription.revoke": true, "subscription.link": true,
	"source.create": true, "source.accept": true, "source.refresh": true, "source.pause": true, "source.refreshed": true,
	"node.vpn_configured": true, "access.vpn_config_exported": true,
	"node.vpn_policy_issued":   true,
	"node.certificate_renewed": true, "node.command_created": true, "node.command_recorded": true,
	"node.created": true, "node.enrollment_created": true, "node.enrolled": true, "node.revoked": true,
	"access.user_created": true, "access.user_state": true, "access.entitlement_changed": true, "access.block_added": true, "access.block_cleared": true, "access.challenge_created": true, "access.device_registered": true, "access.device_revoked": true, "access.credential_rotated": true, "access.entitlement_expired": true,
	"job.enqueued": true, "job.succeeded": true, "job.retry_scheduled": true, "job.failed": true,
	"identity.bootstrap_prepared": true, "identity.bootstrap_completed": true,
	"identity.login_succeeded": true, "identity.login_failed": true, "identity.logout": true,
	"identity.sessions_revoked": true, "identity.admin_created": true, "identity.admin_updated": true,
}

func valid(actorID, action, targetID, outcome string) bool {
	actor := database.ValidID(actorID) || actorID == "system" || actorID == "worker" || actorID == "anonymous"
	return actor && actions[action] && (targetID == "" || database.ValidID(targetID)) &&
		(outcome == "accepted" || outcome == "succeeded" || outcome == "failed")
}

func Append(ctx context.Context, tx pgx.Tx, actorID, action, targetID, outcome string) error {
	if !valid(actorID, action, targetID, outcome) {
		return ErrInvalid
	}
	id, err := database.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,actor_id,action,target_id,outcome) VALUES($1,$2,$3,$4,$5)`, id, actorID, action, targetID, outcome)
	return err
}

type Entry struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	Outcome   string    `json:"outcome"`
	CreatedAt time.Time `json:"created_at"`
}
type Store struct{ Pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

func (s *Store) List(ctx context.Context, limit int, beforeID string) ([]Entry, error) {
	if limit < 1 || limit > 100 || (beforeID != "" && !database.ValidID(beforeID)) {
		return nil, ErrInvalid
	}
	var cursorTime time.Time
	if beforeID != "" {
		if err := s.Pool.QueryRow(ctx, `SELECT created_at FROM audit_events WHERE id=$1`, beforeID).Scan(&cursorTime); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT id::text,actor_id,action,target_id,outcome,created_at FROM audit_events
WHERE $1='' OR (created_at,id)<($2, NULLIF($1,'')::uuid) ORDER BY created_at DESC,id DESC LIMIT $3`, beforeID, cursorTime, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Entry{}
	for rows.Next() {
		var e Entry
		if err = rows.Scan(&e.ID, &e.ActorID, &e.Action, &e.TargetID, &e.Outcome, &e.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	return list, rows.Err()
}
