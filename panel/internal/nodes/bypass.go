package nodes

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/bypasslease"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
	"time"
)

// BypassSession authenticates the live certificate in the coordinator's own
// transaction. An enrolled engine is trusted to attest its protected handshake;
// this API must never be exposed as a direct client/session-cookie endpoint.
func (s *Store) BypassSession(ctx context.Context, cert *x509.Certificate, q nodewire.BypassRequest) (nodewire.BypassResponse, error) {
	out := nodewire.BypassResponse{SchemaVersion: 1, NodeID: q.NodeID, InstallationID: q.InstallationID, EngineEpoch: q.EngineEpoch, Nonce: q.Nonce, Operation: q.Operation}
	if q.SchemaVersion != 1 || !database.ValidID(q.Nonce) || !database.ValidID(q.NodeID) || !database.ValidID(q.InstallationID) || !engineEpochPattern.MatchString(q.EngineEpoch) {
		return out, ErrInvalid
	}
	if q.Operation == "fence" {
		if !q.PreviousEngineStopped || q.CredentialID != "" || q.RequestID != "" || q.UserID != "" || q.Generation != 0 || q.Revision != 0 {
			return out, ErrInvalid
		}
	} else if !database.ValidID(q.CredentialID) || q.PreviousEngineStopped {
		return out, ErrInvalid
	} else if q.Operation == "claim" {
		if !database.ValidID(q.RequestID) || q.UserID != "" || q.Generation != 0 || q.Revision != 0 {
			return out, ErrInvalid
		}
	} else {
		if q.RequestID != "" || !database.ValidID(q.UserID) || q.Generation < 1 || q.Generation > bypasslease.MaxSequence {
			return out, ErrInvalid
		}
		if q.Operation != "renew" && q.Revision != 0 {
			return out, ErrInvalid
		}
	}
	o := bypasslease.Owner{NodeID: q.NodeID, InstallationID: q.InstallationID, EngineEpoch: q.EngineEpoch, CredentialID: q.CredentialID}
	leases := bypasslease.Authenticated(s.Pool, func(ctx context.Context, tx pgx.Tx, owner bypasslease.Owner) error {
		if err := s.lockAuthorizedNode(ctx, tx, cert, owner.NodeID); err != nil {
			return err
		}
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT COALESCE(endpoint->>'account_session'='true',false) FROM nodes_vpn_installations WHERE node_id=$1`, owner.NodeID).Scan(&enabled); err != nil {
			return err
		}
		if !enabled {
			return ErrConflict
		}
		return nil
	})
	if q.Operation == "fence" {
		err := leases.AcknowledgePreviousEngine(ctx, o)
		if err == nil {
			out.State = "fenced"
		}
		return out, err
	}
	r := bypasslease.Ref{UserID: q.UserID, Generation: q.Generation}
	var l bypasslease.Lease
	var err error
	switch q.Operation {
	case "claim":
		l, err = leases.ClaimExplicit(ctx, o, q.RequestID)
	case "activate":
		l, err = leases.Activate(ctx, o, r)
	case "renew":
		l, err = leases.Renew(ctx, o, r, q.Revision)
	case "status":
		l, err = leases.Status(ctx, o, r)
	case "closed":
		l, err = leases.AcknowledgeClosed(ctx, o, r)
	default:
		return out, ErrInvalid
	}
	if err != nil {
		for _, known := range []error{bypasslease.ErrInvalid, bypasslease.ErrDenied, bypasslease.ErrConflict, bypasslease.ErrStale, bypasslease.ErrPending, bypasslease.ErrExpired, bypasslease.ErrClock} {
			if errors.Is(err, known) {
				out.Code = known.Error()
				return out, nil
			}
		}
		return out, err
	}
	out.UserID, out.Generation, out.Revision, out.State, out.Reason = l.UserID, l.Generation, l.Revision, l.State, l.Reason
	// This response cannot grant a fresh full TTL to an old activation retry.
	// The receiving node also anchors it to the local request start and nonce.
	if l.State == "active" && (q.Operation == "activate" || q.Operation == "renew") {
		var now time.Time
		if err = s.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return nodewire.BypassResponse{}, err
		}
		out.RemainingMS = max(0, min(bypasslease.LeaseTTL.Milliseconds(), l.ExpiresAt.Sub(now).Milliseconds()))
	}
	return out, nil
}
