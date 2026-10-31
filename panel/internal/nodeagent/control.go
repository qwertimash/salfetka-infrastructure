package nodeagent

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"

	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

func (a *Agent) loadControl() error {
	if a.cfg.SignerPublicFile != "" {
		raw, err := readExternal(a.cfg.SignerPublicFile, false)
		if err != nil {
			return fault("node_control_signer_unreadable")
		}
		a.signer, err = nodecontrol.LoadPublicKey(raw)
		if err != nil {
			return fault("node_control_signer_invalid")
		}
	}
	c := a.state.Control
	if c == nil {
		return nil
	}
	if a.signer == nil {
		return fault("node_control_signer_required")
	}
	if c.SignerHash != digest(a.signer) {
		return fault("node_control_signer_changed")
	}
	if c.AuthorityEpoch != 1 || c.Generation < 0 || c.AppliedGeneration < 0 || c.AppliedGeneration > c.Generation || c.WallHighWater.IsZero() {
		return fault("node_control_state_invalid")
	}
	if c.ActiveConfig != nil && (c.ActiveConfig.HeartbeatIntervalSeconds < 5 || c.ActiveConfig.HeartbeatIntervalSeconds > 30 || c.AppliedGeneration == 0) {
		return fault("node_control_state_invalid")
	}
	if c.ActiveConfig == nil && c.AppliedGeneration != 0 {
		return fault("node_control_state_invalid")
	}
	if c.AppliedGeneration == 0 {
		if c.AppliedEnvelope != nil {
			return fault("node_control_state_invalid")
		}
	} else {
		if c.AppliedEnvelope == nil {
			return fault("node_control_state_invalid")
		}
		applied, err := nodecontrol.Verify(a.signer, *c.AppliedEnvelope)
		if err != nil || applied.NodeID != a.state.NodeID || applied.AuthorityEpoch != c.AuthorityEpoch || applied.Generation != c.AppliedGeneration || c.ActiveConfig == nil || *c.ActiveConfig != applied.Payload {
			return fault("node_control_state_invalid")
		}
	}
	if c.Generation == 0 {
		if c.Phase != "idle" || c.Envelope != nil || c.Receipt != nil || c.ReceiptPending || c.PayloadHash != "" {
			return fault("node_control_state_invalid")
		}
		return nil
	}
	if c.Envelope == nil {
		return fault("node_control_state_invalid")
	}
	cmd, err := nodecontrol.Verify(a.signer, *c.Envelope)
	if err != nil || cmd.NodeID != a.state.NodeID || cmd.Generation != c.Generation || cmd.AuthorityEpoch != c.AuthorityEpoch || nodecontrol.CommandHash(*c.Envelope) != c.PayloadHash {
		return fault("node_control_state_invalid")
	}
	if c.Phase == "accepted" {
		if c.Receipt != nil || c.ReceiptPending || c.AppliedGeneration >= c.Generation {
			return fault("node_control_state_invalid")
		}
		return nil
	}
	r := c.Receipt
	if r == nil || r.SchemaVersion != 1 || r.NodeID != cmd.NodeID || r.OperationID != cmd.OperationID || r.AuthorityEpoch != cmd.AuthorityEpoch || r.Generation != cmd.Generation || r.CommandSHA256 != c.PayloadHash || r.CompletedAt.IsZero() {
		return fault("node_control_state_invalid")
	}
	switch c.Phase {
	case "applied":
		if r.Status != "applied" || r.ErrorCode != "" || r.Config == nil || *r.Config != cmd.Payload || c.ActiveConfig == nil || *c.ActiveConfig != cmd.Payload || c.AppliedGeneration != c.Generation {
			return fault("node_control_state_invalid")
		}
		if r.CompletedAt.Before(cmd.CreatedAt.Add(-time.Second)) || r.CompletedAt.After(cmd.DeadlineAt) || r.CompletedAt.After(c.WallHighWater) {
			return fault("node_control_state_invalid")
		}
	case "failed":
		if r.Status != "failed" || r.Config != nil || c.AppliedGeneration >= c.Generation {
			return fault("node_control_state_invalid")
		}
		switch r.ErrorCode {
		case "deadline_exceeded", "clock_rollback", "apply_failed", "readback_mismatch":
		default:
			return fault("node_control_state_invalid")
		}
	default:
		return fault("node_control_state_invalid")
	}
	return nil
}

func (a *Agent) withWall(next localState) localState {
	if next.Control != nil {
		copy := *next.Control
		copy.WallHighWater = laterWall(copy.WallHighWater, a.now())
		next.Control = &copy
	}
	return next
}
func (a *Agent) saveControl(next localState) error {
	if a.storagePoisoned {
		return fault("node_control_storage_failed")
	}
	next = a.withWall(next)
	if a.persist(a.dir, next) != nil {
		// Rename may have committed before directory fsync failed. Continuing
		// with the old in-memory watermark could roll back that committed state.
		a.storagePoisoned = true
		return fault("node_control_storage_failed")
	}
	a.state = next
	return nil
}
func (a *Agent) EffectiveInterval() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Control != nil && a.state.Control.ActiveConfig != nil {
		return time.Duration(a.state.Control.ActiveConfig.HeartbeatIntervalSeconds) * time.Second
	}
	return a.cfg.HeartbeatInterval
}
func (a *Agent) Readback() *nodewire.Receipt {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Control == nil || a.state.Control.Receipt == nil {
		return nil
	}
	r := *a.state.Control.Receipt
	if r.Config != nil {
		cfg := *r.Config
		r.Config = &cfg
	}
	return &r
}
func controlFailure(err error) error {
	return fault("node_control_" + strings.TrimPrefix(err.Error(), "node_"))
}

// SyncControl keeps one immutable pending receipt. It drains that receipt before
// requesting a newer intent; a failed ACK cannot drop an earlier result.
func (a *Agent) SyncControl(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.storagePoisoned {
		return fault("node_control_storage_failed")
	}
	if a.closed {
		return fault("node_control_agent_closed")
	}
	if a.signer == nil {
		return nil
	}
	if a.state.Enrollment == nil {
		return fault("node_control_not_enrolled")
	}
	key, err := parseKey(a.state.PrivateKeyPEM)
	if err != nil {
		return controlFailure(err)
	}
	if _, err = verifyEnrollment(*a.state.Enrollment, a.state.NodeID, key); err != nil {
		return controlFailure(err)
	}
	if a.state.Control == nil {
		next := a.state
		next.SchemaVersion = 2
		next.Control = &controlWatermark{AuthorityEpoch: 1, SignerHash: digest(a.signer), Phase: "idle", WallHighWater: a.now().UTC()}
		if err := a.saveControl(next); err != nil {
			return err
		}
	}
	if a.state.Control.Phase == "accepted" {
		if err := a.finishAccepted(); err != nil {
			return err
		}
	}
	if a.state.Control.ReceiptPending {
		if err := a.ackReceipt(ctx); err != nil {
			return err
		}
	}
	var desired nodewire.DesiredResponse
	if err := a.request(ctx, http.MethodGet, nodewire.DesiredPath+"?node_id="+a.state.NodeID, nil, &desired); err != nil {
		return controlFailure(err)
	}
	if desired.SchemaVersion != 1 || desired.NodeID != a.state.NodeID {
		return fault("node_control_response_mismatch")
	}
	if desired.Command == nil {
		return nil
	}
	cmd, err := nodecontrol.Verify(a.signer, *desired.Command)
	if err != nil {
		return fault("node_control_invalid_command")
	}
	if cmd.NodeID != a.state.NodeID {
		return fault("node_control_wrong_node")
	}
	c := a.state.Control
	hash := nodecontrol.CommandHash(*desired.Command)
	if cmd.Generation < c.Generation {
		return fault("node_control_stale_generation")
	}
	if cmd.Generation == c.Generation {
		if hash != c.PayloadHash || c.Envelope == nil || !bytes.Equal([]byte(desired.Command.Body), []byte(c.Envelope.Body)) || desired.Command.Signature != c.Envelope.Signature {
			return fault("node_control_generation_conflict")
		}
		// A completed immutable receipt is the read-back for an exact replay.
		if c.Phase == "failed" {
			return fault("node_control_" + c.Receipt.ErrorCode)
		}
		return nil
	}
	next := a.state
	copy := *c
	next.Control = &copy
	envelope := *desired.Command
	copy.Generation = cmd.Generation
	copy.PayloadHash = hash
	copy.Envelope = &envelope
	copy.Phase = "accepted"
	copy.Receipt = nil
	copy.ReceiptPending = false
	if err := a.saveControl(next); err != nil {
		return err
	}
	if err := a.finishAccepted(); err != nil {
		return err
	}
	if err := a.ackReceipt(ctx); err != nil {
		return err
	}
	if a.state.Control.Phase == "failed" {
		return fault("node_control_" + a.state.Control.Receipt.ErrorCode)
	}
	return nil
}

func (a *Agent) finishAccepted() error {
	c := a.state.Control
	cmd, err := nodecontrol.Verify(a.signer, *c.Envelope)
	if err != nil {
		return fault("node_control_state_invalid")
	}
	now := a.now().UTC()
	code := ""
	if !a.clockTrusted(c.WallHighWater) || now.Before(cmd.CreatedAt.Add(-time.Second)) {
		code = "clock_rollback"
	} else if !now.Before(cmd.DeadlineAt) {
		code = "deadline_exceeded"
	}
	next := a.state
	copy := *c
	next.Control = &copy
	r := &nodewire.Receipt{SchemaVersion: 1, NodeID: cmd.NodeID, OperationID: cmd.OperationID, AuthorityEpoch: cmd.AuthorityEpoch, Generation: cmd.Generation, CommandSHA256: c.PayloadHash, CompletedAt: laterWall(now, c.WallHighWater), Status: "failed", ErrorCode: code}
	copy.Phase = "failed"
	if code == "" {
		cfg := cmd.Payload
		copy.ActiveConfig = &cfg
		copy.AppliedGeneration = cmd.Generation
		copy.AppliedEnvelope = c.Envelope
		copy.Phase = "applied"
		r.Status = "applied"
		r.Config = &cfg
	}
	copy.Receipt = r
	copy.ReceiptPending = true
	// This setting has no external side effect: committing active_config and
	// its receipt atomically publishes the setting under a.mu. Restart reads
	// the same active value before reporting anything to the server.
	return a.saveControl(next)
}
func (a *Agent) ackReceipt(ctx context.Context) error {
	var response nodewire.ReceiptResponse
	r := a.state.Control.Receipt
	if err := a.post(ctx, nodewire.ReceiptsPath, r, &response); err != nil {
		return controlFailure(err)
	}
	if response.SchemaVersion != 1 || response.NodeID != r.NodeID || response.OperationID != r.OperationID || response.Status != "recorded" {
		return fault("node_control_response_mismatch")
	}
	next := a.state
	copy := *next.Control
	next.Control = &copy
	copy.ReceiptPending = false
	return a.saveControl(next)
}
