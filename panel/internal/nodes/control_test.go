package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"sync"
	"testing"
	"time"
)

func controlFixture(t *testing.T) *fixture {
	f := newFixture(t)
	raw, e := nodecontrol.GenerateSigner()
	if e != nil {
		t.Fatal(e)
	}
	f.s.Signer, e = nodecontrol.LoadSigner(raw)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) command(n Node, interval int) (CommandCreated, nodewire.Command) {
	f.t.Helper()
	var raw json.RawMessage
	m := f.m(n, "config")
	e := f.tx(func(tx pgx.Tx) error {
		var e error
		raw, _, e = f.s.CreateCommandTx(context.Background(), tx, m, nodewire.AgentConfig{HeartbeatIntervalSeconds: interval})
		return e
	})
	if e != nil {
		f.t.Fatal(e)
	}
	var out CommandCreated
	if e = json.Unmarshal(raw, &out); e != nil {
		f.t.Fatal(e)
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	c, e := nodecontrol.Verify(pub, out.Command)
	if e != nil {
		f.t.Fatal(e)
	}
	return out, c
}
func receiptFor(c nodewire.Command, s nodewire.SignedCommand) nodewire.Receipt {
	p := c.Payload
	return nodewire.Receipt{SchemaVersion: 1, NodeID: c.NodeID, OperationID: c.OperationID, AuthorityEpoch: 1, Generation: c.Generation, CommandSHA256: nodecontrol.CommandHash(s), Status: "applied", Config: &p, CompletedAt: c.CreatedAt.Add(time.Second)}
}
func TestControlSignerBindingConcurrentAndWrongKey(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := BindSigner(ctx, f.p, f.s.Signer); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	raw, _ := nodecontrol.GenerateSigner()
	other, _ := nodecontrol.LoadSigner(raw)
	if e := BindSigner(ctx, f.p, other); !errors.Is(e, ErrKey) {
		t.Fatal("wrong signer replaced binding", e)
	}
}
func TestControlAtomicCASIdempotencyAndImmutableSnapshots(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, _ := enrolled(t, f)
	m := f.m(n, "config")
	var wg sync.WaitGroup
	results := make(chan []byte, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var raw json.RawMessage
			e := f.tx(func(tx pgx.Tx) error {
				var e error
				raw, _, e = f.s.CreateCommandTx(ctx, tx, m, nodewire.AgentConfig{HeartbeatIntervalSeconds: 5})
				return e
			})
			if e != nil {
				t.Error(e)
				return
			}
			results <- raw
		}()
	}
	wg.Wait()
	close(results)
	var original []byte
	for r := range results {
		if original == nil {
			original = r
		} else if !bytes.Equal(original, r) {
			t.Fatal("replay response changed")
		}
	}
	if len(original) == 0 {
		t.Fatal("no result")
	}
	if got := f.get(n.ID).Revision; got != n.Revision+1 {
		t.Fatal("duplicate revision", got)
	}
	e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.CreateCommandTx(ctx, tx, m, nodewire.AgentConfig{HeartbeatIntervalSeconds: 6})
		return e
	})
	if !errors.Is(e, ErrConflict) {
		t.Fatal("key payload mismatch", e)
	}
	stale := m
	stale.Key = "new-stale-control-key"
	e = f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.CreateCommandTx(ctx, tx, stale, nodewire.AgentConfig{HeartbeatIntervalSeconds: 5})
		return e
	})
	if !errors.Is(e, ErrRevision) {
		t.Fatal("stale CAS", e)
	}
	// A downstream audit failure must roll back desired generation and revision.
	if _, e = f.p.Exec(ctx, "ALTER TABLE audit_events ADD CONSTRAINT test_command_failure CHECK(action <> 'node.command_created') NOT VALID"); e != nil {
		t.Fatal(e)
	}
	current := f.get(n.ID)
	next := f.m(current, "config")
	e = f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.CreateCommandTx(ctx, tx, next, nodewire.AgentConfig{HeartbeatIntervalSeconds: 6})
		return e
	})
	if e == nil {
		t.Fatal("injected failure not reached")
	}
	var generation int64
	f.p.QueryRow(ctx, "SELECT desired_generation FROM nodes_control_state WHERE node_id=$1", n.ID).Scan(&generation)
	if generation != 1 || f.get(n.ID).Revision != current.Revision {
		t.Fatal("partial mutation committed")
	}
	if _, e = f.p.Exec(ctx, "ALTER TABLE audit_events DROP CONSTRAINT test_command_failure"); e != nil {
		t.Fatal(e)
	}
	e = f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.CreateCommandTx(ctx, tx, next, nodewire.AgentConfig{HeartbeatIntervalSeconds: 6})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"nodes_commands", "nodes_control_mutations"} {
		if _, e = f.p.Exec(ctx, "DELETE FROM "+table); e == nil {
			t.Fatal("immutable snapshot deleted", table)
		}
	}
}
func TestControlReceiptsReplayCrossNodeOrderAndRevocation(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	first, c1 := f.command(n, 5)
	second, c2 := f.command(f.get(n.ID), 6)
	r1 := receiptFor(c1, first.Command)
	r2 := receiptFor(c2, second.Command)
	desired, e := f.s.Desired(ctx, cert, n.ID)
	if e != nil || desired.Command == nil || *desired.Command != second.Command {
		t.Fatal("desired", e)
	}
	var control Control
	f.tx(func(tx pgx.Tx) error { control, e = f.s.GetControlTx(ctx, tx, n.ID); return e })
	if control.Observed != nil {
		t.Fatal("desired claimed observed")
	}
	_, wrongCert := enrolled(t, f)
	if _, _, e = f.s.RecordReceipt(ctx, wrongCert, r2); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("cross node accepted", e)
	}
	wrong := r2
	wrong.Config = &nodewire.AgentConfig{HeartbeatIntervalSeconds: 7}
	if _, _, e = f.s.RecordReceipt(ctx, cert, wrong); !errors.Is(e, ErrConflict) {
		t.Fatal("false readback", e)
	}
	if _, replay, e := f.s.RecordReceipt(ctx, cert, r2); e != nil || replay {
		t.Fatal("first receipt", e)
	}
	if _, replay, e := f.s.RecordReceipt(ctx, cert, r2); e != nil || !replay {
		t.Fatal("lost ACK replay", e)
	}
	wrong = r2
	wrong.CompletedAt = wrong.CompletedAt.Add(time.Second)
	if _, _, e = f.s.RecordReceipt(ctx, cert, wrong); !errors.Is(e, ErrConflict) {
		t.Fatal("conflicting receipt", e)
	}
	if _, _, e = f.s.RecordReceipt(ctx, cert, r1); e != nil {
		t.Fatal("older receipt", e)
	}
	f.tx(func(tx pgx.Tx) error { control, e = f.s.GetControlTx(ctx, tx, n.ID); return e })
	var observed nodewire.Receipt
	json.Unmarshal(control.Observed, &observed)
	if observed.Generation != 2 {
		t.Fatal("observed regressed")
	}
	if _, e = f.p.Exec(ctx, "DELETE FROM nodes_command_receipts"); e == nil {
		t.Fatal("receipt mutable")
	}
	m := f.m(f.get(n.ID), "revoke")
	e = f.tx(func(tx pgx.Tx) error { _, _, e := f.s.RevokeTx(ctx, tx, m); return e })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Desired(ctx, cert, n.ID); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("revoked desired", e)
	}
	if _, _, e = f.s.RecordReceipt(ctx, cert, r2); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("revoked replay", e)
	}
}
func TestControlDelayedACKAndClockFailureCanBeAcknowledged(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	id, _ := database.NewID()
	now := time.Now().UTC().Truncate(time.Second)
	p := nodewire.AgentConfig{HeartbeatIntervalSeconds: 5}
	c := nodewire.Command{SchemaVersion: 1, NodeID: n.ID, OperationID: id, AuthorityEpoch: 1, Generation: 1, CreatedAt: now.Add(-20 * time.Minute), DeadlineAt: now.Add(-10 * time.Minute), Kind: "agent.config.set", PayloadSHA256: nodecontrol.PayloadHash(p), Payload: p}
	s, e := f.s.Signer.Sign(c)
	if e != nil {
		t.Fatal(e)
	}
	e = f.tx(func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO nodes_commands(operation_id,node_id,authority_epoch,generation,body,signature,command_sha256,created_at,deadline_at) VALUES($1,$2,1,1,$3,$4,$5,$6,$7)", id, n.ID, s.Body, s.Signature, nodecontrol.CommandHash(s), c.CreatedAt, c.DeadlineAt)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, "INSERT INTO nodes_control_state(node_id,desired_generation) VALUES($1,1)", n.ID)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	r := receiptFor(c, s)
	late := r
	late.CompletedAt = c.DeadlineAt.Add(time.Second)
	if _, _, e = f.s.RecordReceipt(ctx, cert, late); !errors.Is(e, ErrInvalid) {
		t.Fatal("expired apply accepted", e)
	}
	if _, _, e = f.s.RecordReceipt(ctx, cert, r); e != nil {
		t.Fatal("delayed first ACK denied", e)
	}
	second, c2 := f.command(f.get(n.ID), 6)
	failure := receiptFor(c2, second.Command)
	failure.Status = "failed"
	failure.Config = nil
	failure.ErrorCode = "clock_rollback"
	failure.CompletedAt = time.Now().Add(24 * time.Hour)
	if _, _, e = f.s.RecordReceipt(ctx, cert, failure); e != nil {
		t.Fatal("clock failure permanently unacknowledgeable", e)
	}
	if _, replay, e := f.s.RecordReceipt(ctx, cert, failure); e != nil || !replay {
		t.Fatal("clock receipt replay", e)
	}
}

func TestControlConcurrentCASAndReceiptAtomicity(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	m1, m2 := f.m(n, "config"), f.m(n, "config")
	var wg sync.WaitGroup
	out := make(chan error, 2)
	raws := make(chan json.RawMessage, 2)
	for _, m := range []Mutation{m1, m2} {
		wg.Add(1)
		go func(m Mutation) {
			defer wg.Done()
			var raw json.RawMessage
			e := f.tx(func(tx pgx.Tx) error {
				var e error
				raw, _, e = f.s.CreateCommandTx(ctx, tx, m, nodewire.AgentConfig{HeartbeatIntervalSeconds: 5})
				return e
			})
			out <- e
			if e == nil {
				raws <- raw
			}
		}(m)
	}
	wg.Wait()
	close(out)
	close(raws)
	accepted, conflicts := 0, 0
	for e := range out {
		if e == nil {
			accepted++
		} else if errors.Is(e, ErrRevision) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatal("CAS admitted competing commands")
	}
	var created CommandCreated
	json.Unmarshal(<-raws, &created)
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	c, e := nodecontrol.Verify(pub, created.Command)
	if e != nil {
		t.Fatal(e)
	}
	r := receiptFor(c, created.Command)
	if _, e = f.p.Exec(ctx, "ALTER TABLE audit_events ADD CONSTRAINT test_receipt_failure CHECK(action <> 'node.command_recorded') NOT VALID"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.s.RecordReceipt(ctx, cert, r); e == nil {
		t.Fatal("injected receipt failure not reached")
	}
	var count, observed int
	f.p.QueryRow(ctx, "SELECT count(*) FROM nodes_command_receipts").Scan(&count)
	f.p.QueryRow(ctx, "SELECT observed_generation FROM nodes_control_state WHERE node_id=$1", n.ID).Scan(&observed)
	if count != 0 || observed != 0 {
		t.Fatal("partial receipt committed")
	}
	if _, e = f.p.Exec(ctx, "ALTER TABLE audit_events DROP CONSTRAINT test_receipt_failure"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, e := f.s.RecordReceipt(ctx, cert, r); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	f.p.QueryRow(ctx, "SELECT count(*) FROM nodes_command_receipts").Scan(&count)
	if count != 1 {
		t.Fatal("duplicate receipts")
	}
	f.p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='node.command_recorded'").Scan(&count)
	if count != 1 {
		t.Fatal("duplicate receipt audit")
	}
}
