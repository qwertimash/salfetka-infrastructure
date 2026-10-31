package nodes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

func BindSigner(ctx context.Context, pool *pgxpool.Pool, signer *nodecontrol.Signer) error {
	if pool == nil || signer == nil {
		return ErrKey
	}
	pub, err := nodecontrol.LoadPublicKey(signer.PublicPEM())
	if err != nil {
		return ErrKey
	}
	hash := sha256.Sum256(pub)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrKey
	}
	defer database.Rollback(tx)
	if _, err = tx.Exec(ctx, "INSERT INTO nodes_signer_state(singleton,fingerprint) VALUES(true,$1) ON CONFLICT(singleton) DO NOTHING", hash[:]); err != nil {
		return ErrKey
	}
	var stored []byte
	if err = tx.QueryRow(ctx, "SELECT fingerprint FROM nodes_signer_state WHERE singleton").Scan(&stored); err != nil || !bytes.Equal(stored, hash[:]) {
		return ErrKey
	}
	return tx.Commit(ctx)
}

type Control struct {
	NodeID       string                  `json:"node_id"`
	NodeRevision int64                   `json:"node_revision"`
	Desired      *nodewire.SignedCommand `json:"desired"`
	Observed     json.RawMessage         `json:"observed"`
}
type CommandCreated struct {
	NodeID       string                 `json:"node_id"`
	NodeRevision int64                  `json:"node_revision"`
	Command      nodewire.SignedCommand `json:"command"`
}

func (s *Store) CreateCommandTx(ctx context.Context, tx pgx.Tx, m Mutation, config nodewire.AgentConfig) (json.RawMessage, bool, error) {
	if !database.ValidID(m.ActorID) || !database.ValidID(m.TargetID) || !idempotencyPattern.MatchString(m.Key) || len(m.Route) > 100 || m.Revision < 1 || config.HeartbeatIntervalSeconds < 5 || config.HeartbeatIntervalSeconds > 30 {
		return nil, false, ErrInvalid
	}
	if s.Signer == nil {
		return nil, false, ErrKey
	}
	raw, _ := json.Marshal(struct {
		Revision int64
		Config   nodewire.AgentConfig
	}{m.Revision, config})
	hash := sha256.Sum256(raw)
	scope := m.ActorID + "/" + m.Route + "/" + m.TargetID + "/" + m.Key
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,4))", scope); err != nil {
		return nil, false, err
	}
	var oldHash []byte
	var result string
	err := tx.QueryRow(ctx, "SELECT request_hash,result_body FROM nodes_control_mutations WHERE actor_id=$1 AND route=$2 AND target_id=$3 AND idempotency_key=$4", m.ActorID, m.Route, m.TargetID, m.Key).Scan(&oldHash, &result)
	if err == nil {
		if subtle.ConstantTimeCompare(hash[:], oldHash) != 1 {
			return nil, false, ErrConflict
		}
		return json.RawMessage(result), true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	var revision int64
	var state string
	var now time.Time
	err = tx.QueryRow(ctx, "SELECT revision,state,date_trunc('second',clock_timestamp()) FROM nodes_registry WHERE id=$1 FOR UPDATE", m.TargetID).Scan(&revision, &state, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if revision != m.Revision {
		return nil, false, ErrRevision
	}
	if state != "active" {
		return nil, false, ErrConflict
	}
	if _, err = tx.Exec(ctx, "INSERT INTO nodes_control_state(node_id) VALUES($1) ON CONFLICT(node_id) DO NOTHING", m.TargetID); err != nil {
		return nil, false, err
	}
	var generation int64
	if err = tx.QueryRow(ctx, "UPDATE nodes_control_state SET desired_generation=desired_generation+1 WHERE node_id=$1 RETURNING desired_generation", m.TargetID).Scan(&generation); err != nil {
		return nil, false, err
	}
	id, err := database.NewID()
	if err != nil {
		return nil, false, err
	}
	command := nodewire.Command{SchemaVersion: 1, NodeID: m.TargetID, OperationID: id, AuthorityEpoch: 1, Generation: generation, CreatedAt: now, DeadlineAt: now.Add(10 * time.Minute), Kind: "agent.config.set", PayloadSHA256: nodecontrol.PayloadHash(config), Payload: config}
	signed, err := s.Signer.Sign(command)
	if err != nil {
		return nil, false, ErrInvalid
	}
	if _, err = tx.Exec(ctx, "INSERT INTO nodes_commands(operation_id,node_id,authority_epoch,generation,body,signature,command_sha256,created_at,deadline_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8)", id, m.TargetID, generation, signed.Body, signed.Signature, nodecontrol.CommandHash(signed), now, command.DeadlineAt); err != nil {
		return nil, false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE nodes_registry SET revision=revision+1,updated_at=clock_timestamp() WHERE id=$1", m.TargetID); err != nil {
		return nil, false, err
	}
	if err = audit.Append(ctx, tx, m.ActorID, "node.command_created", m.TargetID, "accepted"); err != nil {
		return nil, false, err
	}
	raw, err = json.Marshal(CommandCreated{m.TargetID, revision + 1, signed})
	if err != nil {
		return nil, false, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO nodes_control_mutations(actor_id,route,target_id,idempotency_key,request_hash,result_body) VALUES($1,$2,$3,$4,$5,$6)", m.ActorID, m.Route, m.TargetID, m.Key, hash[:], string(raw)); err != nil {
		return nil, false, err
	}
	return raw, false, nil
}
func (s *Store) GetControlTx(ctx context.Context, tx pgx.Tx, id string) (Control, error) {
	out := Control{NodeID: id}
	if !database.ValidID(id) {
		return out, ErrInvalid
	}
	err := tx.QueryRow(ctx, "SELECT revision FROM nodes_registry WHERE id=$1 FOR SHARE", id).Scan(&out.NodeRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	var body, signature string
	err = tx.QueryRow(ctx, "SELECT c.body,c.signature FROM nodes_commands c JOIN nodes_control_state s ON s.node_id=c.node_id AND s.desired_generation=c.generation WHERE c.node_id=$1", id).Scan(&body, &signature)
	if err == nil {
		out.Desired = &nodewire.SignedCommand{Body: body, Signature: signature}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	var receipt string
	err = tx.QueryRow(ctx, "SELECT r.body FROM nodes_command_receipts r JOIN nodes_control_state s ON s.observed_operation_id=r.operation_id WHERE s.node_id=$1", id).Scan(&receipt)
	if err == nil {
		if !json.Valid([]byte(receipt)) {
			return out, ErrInvalid
		}
		out.Observed = json.RawMessage(receipt)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	return out, nil
}

// lockAuthorizedNode serializes every control call with revocation and checks the
// current DB identity even on an already-established TLS connection.
func (s *Store) lockAuthorizedNode(ctx context.Context, tx pgx.Tx, cert *x509.Certificate, id string) error {
	if err := s.authorizeLeaf(cert, id); err != nil {
		return err
	}
	var state string
	var serial *string
	var pub []byte
	var expires *time.Time
	var now time.Time
	err := tx.QueryRow(ctx, "SELECT state,serial,public_key,certificate_expires_at,clock_timestamp() FROM nodes_registry WHERE id=$1 FOR UPDATE", id).Scan(&state, &serial, &pub, &expires, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if state != "active" || serial == nil || expires == nil || subtle.ConstantTimeCompare(pub, cert.PublicKey.(ed25519.PublicKey)) != 1 {
		return ErrUnauthorized
	}
	allowed, err := s.serialAuthorized(ctx, tx, id, cert, serial, expires, now)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrUnauthorized
	}
	return nil
}
func (s *Store) Desired(ctx context.Context, cert *x509.Certificate, id string) (nodewire.DesiredResponse, error) {
	out := nodewire.DesiredResponse{SchemaVersion: 1, NodeID: id}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer database.Rollback(tx)
	if err = s.lockAuthorizedNode(ctx, tx, cert, id); err != nil {
		return out, err
	}
	control, err := s.GetControlTx(ctx, tx, id)
	if err != nil {
		return out, err
	}
	out.Command = control.Desired
	err = tx.Commit(ctx)
	return out, err
}
func validReceipt(r nodewire.Receipt) bool {
	if r.SchemaVersion != 1 || !database.ValidID(r.NodeID) || !database.ValidID(r.OperationID) || r.AuthorityEpoch != 1 || r.Generation < 1 || r.Generation > 9007199254740991 || len(r.CommandSHA256) != 64 || r.CompletedAt.IsZero() {
		return false
	}
	switch r.Status {
	case "applied":
		return r.Config != nil && r.ErrorCode == ""
	case "failed":
		if r.Config != nil {
			return false
		}
		switch r.ErrorCode {
		case "deadline_exceeded", "clock_rollback", "apply_failed", "readback_mismatch":
			return true
		}
	}
	return false
}
func (s *Store) RecordReceipt(ctx context.Context, cert *x509.Certificate, r nodewire.Receipt) (nodewire.ReceiptResponse, bool, error) {
	out := nodewire.ReceiptResponse{SchemaVersion: 1, NodeID: r.NodeID, OperationID: r.OperationID, Status: "recorded"}
	if !validReceipt(r) {
		return out, false, ErrInvalid
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return out, false, ErrInvalid
	}
	hash := sha256.Sum256(raw)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer database.Rollback(tx)
	if err = s.lockAuthorizedNode(ctx, tx, cert, r.NodeID); err != nil {
		return out, false, err
	}
	var storedHash []byte
	err = tx.QueryRow(ctx, "SELECT body_sha256 FROM nodes_command_receipts WHERE operation_id=$1 AND node_id=$2", r.OperationID, r.NodeID).Scan(&storedHash)
	if err == nil {
		if subtle.ConstantTimeCompare(storedHash, hash[:]) != 1 {
			return out, false, ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return out, false, err
		}
		return out, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, false, err
	}
	var signed nodewire.SignedCommand
	var commandHash string
	var generation int64
	var issued, deadline, now time.Time
	err = tx.QueryRow(ctx, "SELECT body,signature,command_sha256,generation,created_at,deadline_at,clock_timestamp() FROM nodes_commands WHERE operation_id=$1 AND node_id=$2", r.OperationID, r.NodeID).Scan(&signed.Body, &signed.Signature, &commandHash, &generation, &issued, &deadline, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, ErrNotFound
	}
	if err != nil {
		return out, false, err
	}
	if commandHash != r.CommandSHA256 || generation != r.Generation {
		return out, false, ErrConflict
	}
	if r.Status == "applied" {
		if r.CompletedAt.After(now.Add(5*time.Second)) || r.CompletedAt.Before(issued.Add(-5*time.Second)) || r.CompletedAt.After(deadline) {
			return out, false, ErrInvalid
		}
		var command nodewire.Command
		if json.Unmarshal([]byte(signed.Body), &command) != nil || r.Config == nil || *r.Config != command.Payload {
			return out, false, ErrConflict
		}
	}
	if _, err = tx.Exec(ctx, "INSERT INTO nodes_command_receipts(operation_id,node_id,generation,body,body_sha256) VALUES($1,$2,$3,$4,$5)", r.OperationID, r.NodeID, r.Generation, string(raw), hash[:]); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE nodes_control_state SET observed_generation=$2,observed_operation_id=$3 WHERE node_id=$1 AND observed_generation<$2", r.NodeID, r.Generation, r.OperationID); err != nil {
		return out, false, err
	}
	if err = audit.Append(ctx, tx, r.NodeID, "node.command_recorded", r.NodeID, "accepted"); err != nil {
		return out, false, err
	}
	err = tx.Commit(ctx)
	return out, false, err
}
