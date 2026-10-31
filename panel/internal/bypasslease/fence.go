package bypasslease

import (
	"context"
	"salfetka/panel/internal/database"
)

// AcknowledgePreviousEngine is an authenticated installation's attestation that
// it acquired the existing exclusive engine.lock after the prior engine exited.
// This is NOT inferred from a heartbeat, an epoch string or elapsed wall time.
// The node must not clone its identity/state directory onto another live host.
func (s *Store) AcknowledgePreviousEngine(ctx context.Context, o Owner) error {
	if s.authorize == nil || !database.ValidID(o.NodeID) || !database.ValidID(o.InstallationID) || !epochPattern.MatchString(o.EngineEpoch) {
		return ErrDenied
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer database.Rollback(tx)
	if err = s.authorize(ctx, tx, o); err != nil {
		return err
	}
	var ready bool
	err = tx.QueryRow(ctx, `SELECT enabled AND installation_id=$2 AND engine_epoch=$3 AND endpoint->>'backend'='olcrtc' FROM nodes_vpn_installations WHERE node_id=$1 FOR UPDATE`, o.NodeID, o.InstallationID, o.EngineEpoch).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return ErrDenied
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT user_id::text FROM bypass_leases WHERE node_id=$1 AND installation_id=$2 AND engine_epoch<>$3 AND state IN('pending','active','draining') ORDER BY user_id::text`, o.NodeID, o.InstallationID, o.EngineEpoch)
	if err != nil {
		return err
	}
	var users []string
	for rows.Next() {
		var u string
		if err = rows.Scan(&u); err != nil {
			rows.Close()
			return err
		}
		users = append(users, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, u := range users {
		if err = lockUser(ctx, tx, u); err != nil {
			return err
		}
		// A fenced restart may resume only the latest explicit intent on the
		// same installation. It cannot resurrect a replaced generation or
		// transfer ownership from another node. Rebind under the account lock
		// before allowing a handshake; the prior process has been fenced.
		now, e := clock(ctx, tx, u)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `UPDATE bypass_leases SET engine_epoch=$4,state='pending',reason='',revision=revision+1,expires_at=$5
          WHERE user_id=$1 AND node_id=$2 AND installation_id=$3 AND engine_epoch<>$4
          AND state IN('active','pending') AND revision<$6
          AND generation=(SELECT generation FROM bypass_accounts WHERE user_id=$1)`, u, o.NodeID, o.InstallationID, o.EngineEpoch, now.Add(PrepareTTL), MaxSequence)
		if e != nil {
			return e
		}
	}
	_, err = tx.Exec(ctx, `UPDATE bypass_leases SET state=CASE WHEN state='draining' THEN 'replaced' ELSE 'closed' END,reason=CASE WHEN state='draining' THEN 'session_replaced' ELSE 'session_closed' END WHERE node_id=$1 AND installation_id=$2 AND engine_epoch<>$3 AND state IN('pending','active','draining')`, o.NodeID, o.InstallationID, o.EngineEpoch)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
