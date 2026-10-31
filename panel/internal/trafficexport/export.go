// Package trafficexport reads already authenticated panel reports. It never
// polls engines, resets counters, decrypts policies, or changes panel state.
package trafficexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

const MaxBytes = 16 * 1024 * 1024

var ErrInvalid = errors.New("traffic_export_invalid")
var ErrUnavailable = errors.New("traffic_export_unavailable")
var ErrIntegrity = errors.New("traffic_export_integrity")
var ErrMissing = errors.New("traffic_export_node_missing")
var ErrNotCurrent = errors.New("traffic_export_node_not_current")

type Frame struct {
	Source string             `json:"source"`
	Report nodewire.VPNReport `json:"report"`
}
type Document struct {
	SchemaVersion int     `json:"schema_version"`
	Frames        []Frame `json:"frames"`
}

func ValidNodes(ids []string) bool {
	if len(ids) < 1 || len(ids) > 100 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !database.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

type storedReport struct {
	body, node, epoch, installation, state string
	hash                                   []byte
	sequence, generation, desired          int64
	currentEpoch                           *string
	enabled                                bool
}

func decode(row storedReport) (nodewire.VPNReport, error) {
	var r nodewire.VPNReport
	sum := sha256.Sum256([]byte(row.body))
	if len(row.body) > 131072 || !bytes.Equal(sum[:], row.hash) {
		return r, ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewBufferString(row.body))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF ||
		r.Receipt.SchemaVersion != 1 || r.Receipt.Status != "applied" || r.Receipt.ErrorCode != "" ||
		r.Receipt.NodeID != row.node || r.Receipt.InstallationID != row.installation ||
		r.EngineEpoch != row.epoch || r.Sequence != row.sequence || r.Sequence < 1 ||
		r.Receipt.Generation != row.generation || row.generation < 1 ||
		r.Usage == nil || r.Receipt.Usage == nil || r.ObservedAt.IsZero() || r.Receipt.CompletedAt.IsZero() ||
		r.Receipt.CompletedAt.After(r.ObservedAt) {
		return r, ErrIntegrity
	}
	if row.state != "active" || !row.enabled || row.currentEpoch == nil ||
		*row.currentEpoch != r.EngineEpoch || row.desired != row.generation {
		return r, ErrNotCurrent
	}
	for _, usage := range [][]nodewire.VPNUsage{r.Usage, r.Receipt.Usage} {
		seen := map[string]bool{}
		for _, u := range usage {
			if !database.ValidID(u.GrantID) || seen[u.GrantID] ||
				u.InstanceEpoch != r.EngineEpoch || u.Generation != row.generation ||
				(u.Downlink != nil && *u.Downlink < 0) || (u.Uplink != nil && *u.Uplink < 0) {
				return r, ErrIntegrity
			}
			seen[u.GrantID] = true
		}
	}
	return r, nil
}

// Read uses one READ ONLY snapshot, without row locks or migrations. Missing
// requested nodes fail the whole export rather than silently shrinking coverage.
func Read(ctx context.Context, pool *pgxpool.Pool, ids []string) ([]byte, error) {
	if !ValidNodes(ids) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer database.Rollback(tx)
	rows, err := tx.Query(ctx, `SELECT o.body,o.body_sha256,o.node_id::text,o.engine_epoch,o.sequence,o.generation,
 i.installation_id::text,i.engine_epoch,i.generation,i.enabled,n.state
 FROM nodes_vpn_observations o
 JOIN nodes_vpn_installations i ON i.node_id=o.node_id
 JOIN nodes_registry n ON n.id=o.node_id
 WHERE o.node_id=ANY($1::uuid[]) ORDER BY o.node_id`, ids)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	doc := Document{SchemaVersion: 1, Frames: []Frame{}}
	for rows.Next() {
		var row storedReport
		if err = rows.Scan(&row.body, &row.hash, &row.node, &row.epoch, &row.sequence, &row.generation,
			&row.installation, &row.currentEpoch, &row.desired, &row.enabled, &row.state); err != nil {
			return nil, ErrUnavailable
		}
		r, e := decode(row)
		if e != nil {
			return nil, e
		}
		doc.Frames = append(doc.Frames, Frame{Source: "panel", Report: r})
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	if len(doc.Frames) != len(ids) {
		return nil, ErrMissing
	}
	raw, err := json.Marshal(doc)
	if err != nil || len(raw)+1 > MaxBytes {
		return nil, ErrInvalid
	}
	if tx.Commit(ctx) != nil {
		return nil, ErrUnavailable
	}
	return append(raw, '\n'), nil
}
