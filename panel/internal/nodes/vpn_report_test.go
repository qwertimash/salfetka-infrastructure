package nodes

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

func TestVPNReportsReplayEpochCountersAndFreshness(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	installation, _ := database.NewID()
	err := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.ConfigureVPNTx(ctx, tx, f.m(n, "vpn"), installation, access.DefaultGroupID, true)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	seedVPNUser(t, f)
	req := VPNFetch{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, EngineEpoch: strings.Repeat("e", 32)}
	desired, _, err := f.s.VPNDesired(ctx, cert, req)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	policy, _ := nodecontrol.VerifyVPN(pub, *desired.Policy)
	value := int64(100)
	usage := []nodewire.VPNUsage{{GrantID: policy.Grants[0].ID, InstanceEpoch: req.EngineEpoch, Generation: 1, Active: true, Uplink: &value, Downlink: &value}}
	now := time.Now().UTC()
	receipt := nodewire.VPNReceipt{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, Generation: 1, PolicySHA256: nodecontrol.VPNHash(*desired.Policy), Status: "applied", CompletedAt: now, Usage: usage}
	report := nodewire.VPNReport{Receipt: receipt, EngineEpoch: req.EngineEpoch, Sequence: 1, ObservedAt: now, Usage: usage}
	if _, replay, e := f.s.RecordVPN(ctx, cert, report); e != nil || replay {
		t.Fatal("first", e)
	}
	if _, replay, e := f.s.RecordVPN(ctx, cert, report); e != nil || !replay {
		t.Fatal("lost ACK", e)
	}
	status := func() VPNStatus {
		var out VPNStatus
		if e := f.tx(func(tx pgx.Tx) error { var e error; out, e = f.s.VPNStatusTx(ctx, tx, n.ID); return e }); e != nil {
			t.Fatal(e)
		}
		return out
	}
	if status().State != "applied" {
		t.Fatal("missing readback")
	}
	mutated := report
	mutated.ObservedAt = now.Add(time.Millisecond)
	if _, _, e := f.s.RecordVPN(ctx, cert, mutated); !errors.Is(e, ErrConflict) {
		t.Fatal("changed duplicate", e)
	}
	lower := int64(99)
	mutated = report
	mutated.Sequence = 2
	mutated.Usage = append([]nodewire.VPNUsage(nil), report.Usage...)
	mutated.Usage[0].Uplink = &lower
	if _, _, e := f.s.RecordVPN(ctx, cert, mutated); !errors.Is(e, ErrConflict) {
		t.Fatal("counter regression", e)
	}
	higher := int64(200)
	mutated.Usage[0].Uplink = &higher
	if _, _, e := f.s.RecordVPN(ctx, cert, mutated); e != nil {
		t.Fatal("counter advance", e)
	}
	if _, _, e := f.s.RecordVPN(ctx, cert, report); !errors.Is(e, ErrConflict) {
		t.Fatal("out of order", e)
	}
	var receipts int
	f.p.QueryRow(ctx, "SELECT count(*) FROM nodes_vpn_receipts").Scan(&receipts)
	if receipts != 1 {
		t.Fatal("duplicate receipts")
	}
	if _, e := f.p.Exec(ctx, "UPDATE nodes_vpn_receipts SET body=body"); e == nil {
		t.Fatal("receipt mutable")
	}
	if _, e := f.p.Exec(ctx, "UPDATE nodes_vpn_observations SET received_at=clock_timestamp()-interval '1 minute'"); e != nil {
		t.Fatal(e)
	}
	if status().State != "stale" || status().Observed.Usage[0].Uplink == nil {
		t.Fatal("stale values disappeared or appeared live")
	}
	req.EngineEpoch = strings.Repeat("f", 32)
	if _, _, e := f.s.VPNDesired(ctx, cert, req); e != nil {
		t.Fatal(e)
	}
	if _, _, e := f.s.RecordVPN(ctx, cert, mutated); !errors.Is(e, ErrConflict) {
		t.Fatal("retired epoch", e)
	}
	if _, e := f.p.Exec(ctx, "UPDATE nodes_registry SET state='revoked' WHERE id=$1", n.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e := f.s.RecordVPN(ctx, cert, mutated); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("revoked node", e)
	}
}
