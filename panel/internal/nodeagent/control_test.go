package nodeagent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

func controlFixture(t *testing.T) (*fixture, *nodecontrol.Signer, ed25519.PrivateKey) {
	t.Helper()
	f := newFixture(t)
	raw, err := nodecontrol.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := nodecontrol.LoadSigner(raw)
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseKey(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.SignerPublicFile = filepath.Join(filepath.Dir(f.cfg.CAFile), "signer.pub")
	f.cfg.HeartbeatInterval = 15 * time.Second
	mustWrite(t, f.cfg.SignerPublicFile, signer.PublicPEM())
	return f, signer, key
}
func command(t *testing.T, signer *nodecontrol.Signer, generation int64, interval int) nodewire.SignedCommand {
	t.Helper()
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	payload := nodewire.AgentConfig{HeartbeatIntervalSeconds: interval}
	cmd := nodewire.Command{SchemaVersion: 1, NodeID: testNode, OperationID: id, AuthorityEpoch: 1, Generation: generation, CreatedAt: time.Now().UTC().Add(-time.Second), DeadlineAt: time.Now().UTC().Add(time.Minute), Kind: "agent.config.set", PayloadSHA256: nodecontrol.PayloadHash(payload), Payload: payload}
	signed, err := signer.Sign(cmd)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
func enrolledControl(t *testing.T, f *fixture) *Agent {
	t.Helper()
	a := openAgent(t, f.cfg)
	if err := a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}
func syncOK(t *testing.T, a *Agent) {
	t.Helper()
	if err := a.SyncControl(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func mutateCommand(t *testing.T, s nodewire.SignedCommand, key ed25519.PrivateKey, mutate func(*nodewire.Command)) nodewire.SignedCommand {
	t.Helper()
	var cmd nodewire.Command
	if err := json.Unmarshal([]byte(s.Body), &cmd); err != nil {
		t.Fatal(err)
	}
	mutate(&cmd)
	raw, _ := json.Marshal(cmd)
	return nodewire.SignedCommand{Body: string(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte("salfetka-node-command-v1\x00"), raw...)))}
}
func TestControlMigrationLostACKRestartAndReplay(t *testing.T) {
	f, signer, _ := controlFixture(t)
	a := enrolledControl(t, f)
	if a.state.SchemaVersion != 1 {
		t.Fatal("migration happened before opt-in sync")
	}
	signed := command(t, signer, 1, 5)
	f.desired = &signed
	f.dropReceipt = true
	checkCode(t, a.SyncControl(context.Background()), "node_control_connection_failed")
	if a.state.SchemaVersion != 2 || a.state.Control.Phase != "applied" || !a.state.Control.ReceiptPending || a.EffectiveInterval() != 5*time.Second {
		t.Fatal("durable migration/apply before ACK missing")
	}
	first := a.Readback()
	a.Close()
	a = openAgent(t, f.cfg)
	if a.EffectiveInterval() != 5*time.Second {
		t.Fatal("restart reset applied interval")
	}
	writes := 0
	a.persist = func(fd int, s localState) error { writes++; return writeState(fd, s) }
	syncOK(t, a)
	if len(f.controlReceipts) != 2 || !reflect.DeepEqual(f.controlReceipts[0], f.controlReceipts[1]) || !reflect.DeepEqual(first, a.Readback()) {
		t.Fatal("lost ACK changed immutable receipt")
	}
	// Only the pending flag is persisted; exact replay never reapplies.
	if writes != 1 {
		t.Fatalf("exact replay reapplied config (%d writes)", writes)
	}
	syncOK(t, a)
	if writes != 1 {
		t.Fatal("already ACKed replay wrote a new applied state")
	}
	a.Close()
	cfg := f.cfg
	cfg.SignerPublicFile = ""
	_, err := Open(cfg)
	checkCode(t, err, "node_control_signer_required")
	other, _, _ := controlFixture(t)
	cfg = f.cfg
	cfg.SignerPublicFile = other.cfg.SignerPublicFile
	_, err = Open(cfg)
	checkCode(t, err, "node_control_signer_changed")
}
func TestControlPendingACKDrainedBeforeNewDesired(t *testing.T) {
	f, signer, _ := controlFixture(t)
	a := enrolledControl(t, f)
	one := command(t, signer, 1, 5)
	two := command(t, signer, 2, 30)
	f.desired = &one
	f.ackStatus = 503
	checkCode(t, a.SyncControl(context.Background()), "node_control_http_rejected")
	f.desired = &two
	calls := f.desiredCalls
	checkCode(t, a.SyncControl(context.Background()), "node_control_http_rejected")
	if f.desiredCalls != calls || a.state.Control.Generation != 1 {
		t.Fatal("new desired replaced unacknowledged result")
	}
	f.ackStatus = 0
	syncOK(t, a)
	if a.state.Control.Generation != 2 || a.EffectiveInterval() != 30*time.Second || len(f.controlReceipts) != 2 || f.controlReceipts[0].Generation != 1 || f.controlReceipts[1].Generation != 2 {
		t.Fatal("pending result not drained in order")
	}
}
func TestControlStorageFailureAfterRenameCannotRollBackHWM(t *testing.T) {
	for _, phase := range []string{"accepted", "applied"} {
		t.Run(phase, func(t *testing.T) {
			f, signer, _ := controlFixture(t)
			a := enrolledControl(t, f)
			syncOK(t, a)
			signed := command(t, signer, 1, 5)
			f.desired = &signed
			writes := 0
			a.persist = func(fd int, s localState) error {
				writes++
				if err := writeState(fd, s); err != nil {
					return err
				}
				if s.Control.Phase == phase {
					return fault("synthetic_after_rename_failure")
				}
				return nil
			}
			checkCode(t, a.SyncControl(context.Background()), "node_control_storage_failed")
			count := writes
			checkCode(t, a.Heartbeat(context.Background()), "node_control_storage_failed")
			checkCode(t, a.SyncControl(context.Background()), "node_control_storage_failed")
			checkCode(t, a.Enroll(context.Background()), "node_control_storage_failed")
			if writes != count || len(f.controlReceipts) != 0 {
				t.Fatal("poisoned runtime wrote stale state or ACKed")
			}
			a.Close()
			a = openAgent(t, f.cfg)
			if a.state.Control.Generation != 1 || a.state.Control.Phase != phase {
				t.Fatal("durable highwater rolled back")
			}
			syncOK(t, a)
			if a.EffectiveInterval() != 5*time.Second || a.Readback().Status != "applied" || len(f.controlReceipts) != 1 {
				t.Fatal("restart did not recover committed state")
			}
		})
	}
}
func TestControlAcceptedCrashExpiryAndClockRollback(t *testing.T) {
	for _, reason := range []string{"deadline_exceeded", "clock_rollback"} {
		t.Run(reason, func(t *testing.T) {
			f, signer, _ := controlFixture(t)
			a := enrolledControl(t, f)
			syncOK(t, a)
			signed := command(t, signer, 1, 5)
			f.desired = &signed
			a.persist = func(fd int, s localState) error {
				if s.Control.Phase == "applied" {
					return fault("synthetic_before_apply_write")
				}
				return writeState(fd, s)
			}
			checkCode(t, a.SyncControl(context.Background()), "node_control_storage_failed")
			a.Close()
			a = openAgent(t, f.cfg)
			if a.state.Control.Phase != "accepted" {
				t.Fatal("accepted crash fixture wrong")
			}
			var cmd nodewire.Command
			json.Unmarshal([]byte(signed.Body), &cmd)
			wall := cmd.DeadlineAt.Add(time.Second)
			if reason == "clock_rollback" {
				wall = a.state.Control.WallHighWater.Add(-time.Second)
			}
			a.now = func() time.Time { return wall }
			a.anchorWall = wall
			a.anchorMono = time.Now()
			checkCode(t, a.SyncControl(context.Background()), "node_control_"+reason)
			if a.state.Control.Generation != 1 || a.state.Control.Phase != "failed" || a.EffectiveInterval() != 15*time.Second || a.Readback().ErrorCode != reason || len(f.controlReceipts) != 1 {
				t.Fatal("pending recovery lost HWM/failure or applied expired config")
			}
			first := a.Readback()
			checkCode(t, a.SyncControl(context.Background()), "node_control_"+reason)
			if !reflect.DeepEqual(first, a.Readback()) {
				t.Fatal("failure replay changed receipt")
			}
		})
	}
}
func TestControlRejectsForeignStaleConflictAndTamperedCommands(t *testing.T) {
	f, signer, key := controlFixture(t)
	a := enrolledControl(t, f)
	good := command(t, signer, 2, 5)
	f.desired = &good
	syncOK(t, a)
	for _, kind := range []string{"stale", "conflict", "wrong_node", "epoch", "signature", "payload"} {
		t.Run(kind, func(t *testing.T) {
			candidate := good
			want := "node_control_invalid_command"
			switch kind {
			case "stale":
				candidate = command(t, signer, 1, 5)
				want = "node_control_stale_generation"
			case "conflict":
				candidate = command(t, signer, 2, 30)
				want = "node_control_generation_conflict"
			case "wrong_node":
				candidate = mutateCommand(t, good, key, func(c *nodewire.Command) { c.NodeID = "00000000-0000-4000-8000-000000000002"; c.Generation = 3 })
				want = "node_control_wrong_node"
			case "epoch":
				candidate = mutateCommand(t, good, key, func(c *nodewire.Command) { c.AuthorityEpoch = 2; c.Generation = 3 })
			case "signature":
				candidate.Body += " "
			case "payload":
				candidate = mutateCommand(t, good, key, func(c *nodewire.Command) {
					c.Generation = 3
					c.Payload.HeartbeatIntervalSeconds = 1
					c.PayloadSHA256 = nodecontrol.PayloadHash(c.Payload)
				})
			}
			f.desired = &candidate
			checkCode(t, a.SyncControl(context.Background()), want)
			if a.state.Control.Generation != 2 || a.EffectiveInterval() != 5*time.Second || len(f.controlReceipts) != 1 {
				t.Fatal("rejected command changed applied state")
			}
		})
	}
}
func TestControlDeadlineDoesNotExpireAppliedSetting(t *testing.T) {
	f, signer, _ := controlFixture(t)
	a := enrolledControl(t, f)
	signed := command(t, signer, 1, 30)
	f.desired = &signed
	syncOK(t, a)
	first := a.Readback()
	var cmd nodewire.Command
	json.Unmarshal([]byte(signed.Body), &cmd)
	wall := cmd.DeadlineAt.Add(time.Hour)
	a.now = func() time.Time { return wall }
	syncOK(t, a)
	if a.EffectiveInterval() != 30*time.Second || !reflect.DeepEqual(first, a.Readback()) {
		t.Fatal("deadline treated as active setting lease")
	}
}
func TestControlRunChangesRealHeartbeatInterval(t *testing.T) {
	f, signer, _ := controlFixture(t)
	a := enrolledControl(t, f)
	signed := command(t, signer, 1, 5)
	f.desired = &signed
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	count := 0
	if err := a.Run(ctx, func(code string) {
		if code == "node_heartbeat_recorded" {
			count++
			if count == 2 {
				cancel()
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.heartbeatTimes) != 2 {
		t.Fatal("runtime did not send second heartbeat at applied interval")
	}
	elapsed := f.heartbeatTimes[1].Sub(f.heartbeatTimes[0])
	if elapsed < 4800*time.Millisecond || elapsed > 8*time.Second {
		t.Fatalf("unexpected applied cadence: %s", elapsed)
	}
}
func TestControlFailureDoesNotHideSuccessfulHeartbeat(t *testing.T) {
	f, _, _ := controlFixture(t)
	a := enrolledControl(t, f)
	f.desiredStatus = 503
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var codes []string
	if err := a.Run(ctx, func(code string) {
		codes = append(codes, code)
		if code == "node_control_http_rejected" {
			cancel()
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(codes, []string{"node_heartbeat_recorded", "node_control_http_rejected"}) {
		t.Fatal("heartbeat and control errors mixed")
	}
}
func TestControlClockBoundAndStrictStateJSON(t *testing.T) {
	base := time.Now().UTC()
	mono := time.Now()
	wall := base
	a := &Agent{now: func() time.Time { return wall }, monotonic: func() time.Time { return mono }, anchorWall: base, anchorMono: mono}
	mono = mono.Add(10 * time.Second)
	wall = base.Add(9500 * time.Millisecond)
	if !a.clockTrusted(base) {
		t.Fatal("one-second monotonic tolerance missing")
	}
	wall = base.Add(8 * time.Second)
	if a.clockTrusted(base) {
		t.Fatal("monotonic rollback ignored")
	}
	wall = base.Add(-time.Millisecond)
	if a.clockTrusted(base) {
		t.Fatal("persisted wall floor ignored")
	}
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{"a":1} {}`} {
		var target map[string]any
		if decodeJSON([]byte(raw), &target) == nil {
			t.Fatal("ambiguous state JSON accepted")
		}
	}
}
func TestControlCorruptV2StateNeverResets(t *testing.T) {
	for _, kind := range []string{"watermark", "receipt", "active", "signer"} {
		t.Run(kind, func(t *testing.T) {
			f, signer, _ := controlFixture(t)
			a := enrolledControl(t, f)
			signed := command(t, signer, 1, 5)
			f.desired = &signed
			syncOK(t, a)
			state := a.state
			a.Close()
			switch kind {
			case "watermark":
				state.Control.Generation = 0
			case "receipt":
				state.Control.Receipt.CommandSHA256 = "wrong"
			case "active":
				state.Control.ActiveConfig.HeartbeatIntervalSeconds = 30
			case "signer":
				state.Control.SignerHash = "wrong"
			}
			raw, _ := json.Marshal(state)
			path := filepath.Join(f.cfg.StateDir, "state.json")
			mustWrite(t, path, raw)
			_, err := Open(f.cfg)
			if err == nil {
				t.Fatal("corrupt control state accepted")
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(raw) {
				t.Fatal("corrupt state reset")
			}
		})
	}
}

func TestControlRetainedAppliedConfigStillRequiresSignedProof(t *testing.T) {
	for _, phase := range []string{"accepted", "failed"} {
		t.Run(phase, func(t *testing.T) {
			f, signer, key := controlFixture(t)
			a := enrolledControl(t, f)
			one := command(t, signer, 1, 5)
			f.desired = &one
			syncOK(t, a)
			two := mutateCommand(t, command(t, signer, 2, 30), key, func(c *nodewire.Command) {
				c.CreatedAt = time.Now().UTC().Add(-2 * time.Minute)
				c.DeadlineAt = time.Now().UTC().Add(-time.Minute)
			})
			f.desired = &two
			if phase == "accepted" {
				a.persist = func(fd int, s localState) error {
					if s.Control.Phase == "failed" {
						return fault("synthetic_before_failure_commit")
					}
					return writeState(fd, s)
				}
				checkCode(t, a.SyncControl(context.Background()), "node_control_storage_failed")
			} else {
				checkCode(t, a.SyncControl(context.Background()), "node_control_deadline_exceeded")
			}
			a.Close()
			a = openAgent(t, f.cfg)
			if a.EffectiveInterval() != 5*time.Second || a.state.Control.Phase != phase {
				t.Fatal("previous applied setting lost")
			}
			state := a.state
			a.Close()
			state.Control.ActiveConfig = &nodewire.AgentConfig{HeartbeatIntervalSeconds: 30}
			raw, _ := json.Marshal(state)
			mustWrite(t, filepath.Join(f.cfg.StateDir, "state.json"), raw)
			_, err := Open(f.cfg)
			checkCode(t, err, "node_control_state_invalid")
		})
	}
}
