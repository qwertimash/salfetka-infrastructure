package nodes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

func (s *Store) vpnPolicyTx(ctx context.Context, tx pgx.Tx, node, installation, epoch string, generation int64) (nodewire.VPNPolicy, string, error) {
	var empty nodewire.VPNPolicy
	if s.Vault == nil || s.Signer == nil {
		return empty, "", ErrKey
	}
	var encrypted []byte
	var digest string
	err := tx.QueryRow(ctx, `SELECT policy_ciphertext,policy_sha256 FROM nodes_vpn_policies WHERE node_id=$1 AND generation=$2 AND engine_epoch=$3`, node, generation, epoch).Scan(&encrypted, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, "", ErrConflict
	}
	if err != nil {
		return empty, "", err
	}
	plain, err := s.Vault.OpenPolicy(encrypted, vpnAAD(node, installation, epoch, generation))
	if err != nil {
		return empty, "", ErrKey
	}
	defer clear(plain)
	var signed nodewire.SignedVPNPolicy
	if json.Unmarshal(plain, &signed) != nil {
		return empty, "", ErrKey
	}
	pub, err := nodecontrol.LoadPublicKey(s.Signer.PublicPEM())
	if err != nil {
		return empty, "", ErrKey
	}
	p, err := nodecontrol.VerifyVPN(pub, signed)
	if err != nil || p.NodeID != node || p.InstallationID != installation || p.EngineEpoch != epoch || p.Generation != generation || nodecontrol.VPNHash(signed) != digest {
		return empty, "", ErrKey
	}
	return p, digest, nil
}
func validVPNUsage(usage []nodewire.VPNUsage, p nodewire.VPNPolicy, at time.Time) bool {
	if usage == nil || len(usage) != len(p.Grants) {
		return false
	}
	for i, u := range usage {
		g := p.Grants[i]
		if u.GrantID != g.ID || u.InstanceEpoch != p.EngineEpoch || u.Generation != p.Generation || u.Active != (g.Enabled && at.Before(g.ExpiresAt)) || (u.Uplink != nil && *u.Uplink < 0) || (u.Downlink != nil && *u.Downlink < 0) {
			return false
		}
	}
	return true
}
func countersAdvance(old, next []nodewire.VPNUsage) bool {
	byID := map[string]nodewire.VPNUsage{}
	for _, u := range old {
		byID[u.GrantID] = u
	}
	for _, u := range next {
		if p, ok := byID[u.GrantID]; ok {
			if p.Uplink != nil && (u.Uplink == nil || *u.Uplink < *p.Uplink) {
				return false
			}
			if p.Downlink != nil && (u.Downlink == nil || *u.Downlink < *p.Downlink) {
				return false
			}
		}
	}
	return true
}

// Every write authenticates the live certificate. Reports from retired epochs or
// older desired generations cannot replace the current observed state.
func (s *Store) RecordVPN(ctx context.Context, cert *x509.Certificate, r nodewire.VPNReport) (nodewire.VPNReportResponse, bool, error) {
	out := nodewire.VPNReportResponse{SchemaVersion: 1, NodeID: r.Receipt.NodeID, EngineEpoch: r.EngineEpoch, Sequence: r.Sequence, Status: "recorded"}
	receipt := r.Receipt
	if receipt.SchemaVersion != 1 || !database.ValidID(receipt.NodeID) || !database.ValidID(receipt.InstallationID) || !engineEpochPattern.MatchString(r.EngineEpoch) || receipt.Generation < 1 || receipt.Generation > 9007199254740991 || r.Sequence < 1 || r.Sequence > 9007199254740991 || receipt.Status != "applied" || receipt.ErrorCode != "" || receipt.CompletedAt.IsZero() || r.ObservedAt.IsZero() {
		return out, false, ErrInvalid
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 131072 {
		return out, false, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	receiptRaw, _ := json.Marshal(receipt)
	receiptHash := sha256.Sum256(receiptRaw)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer database.Rollback(tx)
	if err = s.lockAuthorizedVPN(ctx, tx, cert, receipt.NodeID); err != nil {
		return out, false, err
	}
	var installation string
	var generation int64
	var epoch *string
	var now time.Time
	err = tx.QueryRow(ctx, `SELECT installation_id::text,generation,engine_epoch,clock_timestamp() FROM nodes_vpn_installations WHERE node_id=$1 FOR UPDATE`, receipt.NodeID).Scan(&installation, &generation, &epoch, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, ErrNotFound
	}
	if err != nil {
		return out, false, err
	}
	if installation != receipt.InstallationID || generation != receipt.Generation || epoch == nil || *epoch != r.EngineEpoch {
		return out, false, ErrConflict
	}
	var oldBody string
	var oldHash []byte
	err = tx.QueryRow(ctx, `SELECT body,body_sha256 FROM nodes_vpn_observations WHERE node_id=$1`, receipt.NodeID).Scan(&oldBody, &oldHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, false, err
	}
	var previous nodewire.VPNReport
	if err == nil {
		if json.Unmarshal([]byte(oldBody), &previous) != nil {
			return out, false, ErrInvalid
		}
		if previous.EngineEpoch == r.EngineEpoch {
			if r.Sequence == previous.Sequence {
				if !bytes.Equal(oldHash, digest[:]) {
					return out, false, ErrConflict
				}
				return out, true, tx.Commit(ctx)
			}
			if r.Sequence < previous.Sequence || r.ObservedAt.Before(previous.ObservedAt) || !countersAdvance(previous.Usage, r.Usage) {
				return out, false, ErrConflict
			}
		}
	}
	p, hash, err := s.vpnPolicyTx(ctx, tx, receipt.NodeID, installation, r.EngineEpoch, generation)
	if err != nil {
		return out, false, err
	}
	if receipt.PolicySHA256 != hash || receipt.CompletedAt.Before(p.IssuedAt.Add(-time.Second)) || !receipt.CompletedAt.Before(p.ExpiresAt) || receipt.CompletedAt.After(r.ObservedAt) || r.ObservedAt.After(now.Add(5*time.Second)) || r.ObservedAt.Before(now.Add(-30*time.Second)) || !validVPNUsage(receipt.Usage, p, receipt.CompletedAt) || !validVPNUsage(r.Usage, p, r.ObservedAt) || !countersAdvance(receipt.Usage, r.Usage) {
		return out, false, ErrInvalid
	}
	var stored []byte
	err = tx.QueryRow(ctx, `SELECT body_sha256 FROM nodes_vpn_receipts WHERE node_id=$1 AND generation=$2`, receipt.NodeID, generation).Scan(&stored)
	if err == nil {
		if !bytes.Equal(stored, receiptHash[:]) {
			return out, false, ErrConflict
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		if _, err = tx.Exec(ctx, `INSERT INTO nodes_vpn_receipts(node_id,generation,body,body_sha256) VALUES($1,$2,$3,$4)`, receipt.NodeID, generation, string(receiptRaw), receiptHash[:]); err != nil {
			return out, false, err
		}
	} else {
		return out, false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO nodes_vpn_observations(node_id,generation,engine_epoch,sequence,body,body_sha256) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node_id) DO UPDATE SET generation=excluded.generation,engine_epoch=excluded.engine_epoch,sequence=excluded.sequence,body=excluded.body,body_sha256=excluded.body_sha256,received_at=clock_timestamp()`, receipt.NodeID, generation, r.EngineEpoch, r.Sequence, string(raw), digest[:])
	if err != nil {
		return out, false, err
	}
	return out, false, tx.Commit(ctx)
}

type VPNStatus struct {
	NodeID            string              `json:"node_id"`
	Installation      *VPNInstallation    `json:"installation"`
	DesiredGeneration int64               `json:"desired_generation"`
	PolicyExpiresAt   *time.Time          `json:"policy_expires_at"`
	Observed          *nodewire.VPNReport `json:"observed"`
	ReceivedAt        *time.Time          `json:"received_at"`
	State             string              `json:"state"`
}

func (s *Store) VPNStatusTx(ctx context.Context, tx pgx.Tx, id string) (VPNStatus, error) {
	out := VPNStatus{NodeID: id, State: "not_configured"}
	var revision int64
	var state string
	err := tx.QueryRow(ctx, `SELECT revision,state FROM nodes_registry WHERE id=$1 FOR SHARE`, id).Scan(&revision, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	config := VPNInstallation{NodeID: id, NodeRevision: revision}
	var epoch, projection *string
	var endpointJSON []byte
	err = tx.QueryRow(ctx, `SELECT installation_id::text,group_id::text,enabled,generation,policy_expires_at,engine_epoch,projection_sha256,endpoint FROM nodes_vpn_installations WHERE node_id=$1`, id).Scan(&config.InstallationID, &config.GroupID, &config.Enabled, &out.DesiredGeneration, &out.PolicyExpiresAt, &epoch, &projection, &endpointJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if endpointJSON != nil && json.Unmarshal(endpointJSON, &config.Endpoint) != nil {
		return out, ErrInvalid
	}
	out.Installation = &config
	out.State = "pending"
	var body string
	var now time.Time
	err = tx.QueryRow(ctx, `SELECT body,received_at,clock_timestamp() FROM nodes_vpn_observations WHERE node_id=$1`, id).Scan(&body, &out.ReceivedAt, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if json.Unmarshal([]byte(body), &out.Observed) != nil {
		return out, ErrInvalid
	}
	if state != "active" {
		out.State = "node_revoked"
	} else if out.ReceivedAt.Before(now.Add(-20*time.Second)) || out.Observed.ObservedAt.Before(now.Add(-25*time.Second)) || out.PolicyExpiresAt == nil || !out.PolicyExpiresAt.After(now) {
		out.State = "stale"
	} else if projection != nil && out.Observed.Receipt.Generation == out.DesiredGeneration && epoch != nil && *epoch == out.Observed.EngineEpoch {
		out.State = "applied"
	}
	return out, nil
}
