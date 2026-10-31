package nodes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

func (s *Store) RecordConnections(ctx context.Context, cert *x509.Certificate, r nodewire.ConnectionsReport) error {
	if r.SchemaVersion != 1 || !database.ValidID(r.NodeID) || !database.ValidID(r.BootID) || r.Sequence < 1 || r.Sequence > 9007199254740991 || r.PlanRevision < 1 || r.States == nil || len(r.States) > 32 {
		return ErrInvalid
	}
	last := ""
	for _, st := range r.States {
		if !database.ValidID(st.ID) || st.ID <= last || st.Revision < 1 {
			return ErrInvalid
		}
		last = st.ID
		switch st.State {
		case "listening", "disabled":
			if st.ErrorCode != "" {
				return ErrInvalid
			}
		case "failed":
			if st.ErrorCode != "connection_start_failed" && st.ErrorCode != "connection_policy_failed" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer database.Rollback(tx)
	if e = s.lockAuthorizedNode(ctx, tx, cert, r.NodeID); e != nil {
		return e
	}
	var revision int64
	var boot *string
	if e = tx.QueryRow(ctx, "SELECT s.revision,n.current_boot_id::text FROM server_nodes s JOIN nodes_registry n ON n.id=s.node_id WHERE s.node_id=$1", r.NodeID).Scan(&revision, &boot); e != nil {
		return e
	}
	if boot == nil || *boot != r.BootID || revision != r.PlanRevision {
		return ErrConflict
	}
	rows, e := tx.Query(ctx, "SELECT m.connection_id::text,m.revision FROM managed_connections m JOIN nodes_registry n ON n.id=m.connection_id WHERE n.owner_node_id=$1 AND n.state='active' ORDER BY m.connection_id", r.NodeID)
	if e != nil {
		return e
	}
	i := 0
	for rows.Next() {
		var id string
		var rev int64
		if e = rows.Scan(&id, &rev); e != nil {
			rows.Close()
			return e
		}
		if i >= len(r.States) || r.States[i].ID != id || r.States[i].Revision != rev {
			rows.Close()
			return ErrConflict
		}
		i++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if i != len(r.States) {
		return ErrConflict
	}
	raw, _ := json.Marshal(r)
	digest := sha256.Sum256(raw)
	var oldBoot string
	var sequence int64
	var oldHash []byte
	e = tx.QueryRow(ctx, "SELECT boot_id::text,sequence,request_hash FROM managed_connection_observations WHERE node_id=$1", r.NodeID).Scan(&oldBoot, &sequence, &oldHash)
	if e == nil && oldBoot == r.BootID && sequence >= r.Sequence {
		if sequence == r.Sequence && bytes.Equal(oldHash, digest[:]) {
			return tx.Commit(ctx)
		}
		return ErrConflict
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO managed_connection_observations(node_id,boot_id,sequence,plan_revision,request_hash,body) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node_id) DO UPDATE SET boot_id=excluded.boot_id,sequence=excluded.sequence,plan_revision=excluded.plan_revision,request_hash=excluded.request_hash,body=excluded.body,received_at=clock_timestamp()`, r.NodeID, r.BootID, r.Sequence, r.PlanRevision, digest[:], raw)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
