package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/trafficexport"
)

func TestTrafficExportAcceptedReportsIntoPythonObserver(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	installation, _ := database.NewID()
	if e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.ConfigureVPNTx(ctx, tx, f.m(n, "traffic_export"), installation, access.DefaultGroupID, true)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	seedVPNUser(t, f)
	seedVPNUser(t, f)
	req := VPNFetch{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, EngineEpoch: strings.Repeat("a", 32)}
	desired, _, e := f.s.VPNDesired(ctx, cert, req)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	policy, e := nodecontrol.VerifyVPN(pub, *desired.Policy)
	if e != nil || len(policy.Grants) != 2 {
		t.Fatal("two synthetic grants required", e)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	usage := func(a, b, up int64) []nodewire.VPNUsage {
		return []nodewire.VPNUsage{
			{GrantID: policy.Grants[0].ID, InstanceEpoch: req.EngineEpoch, Generation: policy.Generation, Active: true, Uplink: &up, Downlink: &a},
			{GrantID: policy.Grants[1].ID, InstanceEpoch: req.EngineEpoch, Generation: policy.Generation, Active: true, Uplink: &up, Downlink: &b},
		}
	}
	receipt := nodewire.VPNReceipt{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, Generation: policy.Generation,
		PolicySHA256: nodecontrol.VPNHash(*desired.Policy), Status: "applied", CompletedAt: at, Usage: usage(0, 0, 0)}
	report := nodewire.VPNReport{Receipt: receipt, EngineEpoch: req.EngineEpoch, Sequence: 1, ObservedAt: at, Usage: usage(0, 0, 0)}
	if _, _, e = f.s.RecordVPN(ctx, cert, report); e != nil {
		t.Fatal(e)
	}
	// Independent connection defaults to read-only. The exporter must not run
	// migrations, issue update locks, or touch the provider/control-plane path.
	cfg := f.p.Config().Copy()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	reader, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	publisher, e := trafficexport.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer publisher.Close()
	export := func(name string) []byte {
		t.Helper()
		raw, e := trafficexport.Read(ctx, reader, []string{n.ID})
		if e != nil {
			t.Fatal(e)
		}
		if e = publisher.Write(raw); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
		return raw
	}
	base := export("baseline.json")
	report.Sequence = 2
	report.ObservedAt = at.Add(time.Second)
	report.Usage = usage(20_000_000_000, 49_000_000_000, 1_000_000_000_000)
	if _, _, e = f.s.RecordVPN(ctx, cert, report); e != nil {
		t.Fatal(e)
	}
	current := export("current.json")
	if bytes.Equal(base, current) {
		t.Fatal("export reused immutable receipt counters")
	}
	again, e := trafficexport.Read(ctx, reader, []string{n.ID})
	if e != nil || !bytes.Equal(current, again) {
		t.Fatal("export mutated/reset counters", e)
	}
	for _, g := range policy.Grants {
		if g.Credential != "" && bytes.Contains(current, []byte(g.Credential)) {
			t.Fatal("credential leaked")
		}
	}
	missing, _ := database.NewID()
	if _, e = trafficexport.Read(ctx, reader, []string{n.ID, missing}); !errors.Is(e, trafficexport.ErrMissing) {
		t.Fatal("missing requested node hidden", e)
	}
	unchanged, _ := os.ReadFile(filepath.Join(dir, trafficexport.SnapshotName))
	if !bytes.Equal(current, unchanged) {
		t.Fatal("failed read replaced snapshot")
	}
	// Tampered stored bytes cannot be re-published even when valid JSON.
	var oldBody string
	f.p.QueryRow(ctx, "SELECT body FROM nodes_vpn_observations WHERE node_id=$1", n.ID).Scan(&oldBody)
	if _, e = f.p.Exec(ctx, "UPDATE nodes_vpn_observations SET body=body||' ' WHERE node_id=$1", n.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = trafficexport.Read(ctx, reader, []string{n.ID}); !errors.Is(e, trafficexport.ErrIntegrity) {
		t.Fatal(e)
	}
	if _, e = f.p.Exec(ctx, "UPDATE nodes_vpn_observations SET body=$2 WHERE node_id=$1", n.ID, oldBody); e != nil {
		t.Fatal(e)
	}
	// Recreated engine: old snapshot is rejected until a report for the new
	// epoch has been accepted. Counter reset remains an explicit importer gap.
	req.EngineEpoch = strings.Repeat("b", 32)
	desired, _, e = f.s.VPNDesired(ctx, cert, req)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = trafficexport.Read(ctx, reader, []string{n.ID}); !errors.Is(e, trafficexport.ErrNotCurrent) {
		t.Fatal(e)
	}
	policy, e = nodecontrol.VerifyVPN(pub, *desired.Policy)
	if e != nil {
		t.Fatal(e)
	}
	receipt.Generation = policy.Generation
	receipt.PolicySHA256 = nodecontrol.VPNHash(*desired.Policy)
	receipt.CompletedAt = at.Add(2 * time.Second)
	receipt.Usage = usage(0, 0, 0)
	report = nodewire.VPNReport{Receipt: receipt, EngineEpoch: req.EngineEpoch, Sequence: 1, ObservedAt: receipt.CompletedAt, Usage: usage(0, 0, 0)}
	if _, _, e = f.s.RecordVPN(ctx, cert, report); e != nil {
		t.Fatal(e)
	}
	export("restart.json")
	// Real wire JSON produced above is consumed by the shipping Python modules.
	python, e := exec.LookPath("python3")
	if e != nil {
		t.Fatal("Python required for cross-language acceptance")
	}
	script := `
import json, socket, sys
from pathlib import Path
from services.traffic_observation import Observer, initialize
from services.traffic_observation_sources import convert_frames, timestamp
socket.socket.connect = lambda *args: (_ for _ in ()).throw(AssertionError('network forbidden'))
root=Path(sys.argv[1])
docs=[json.loads((root/name).read_text()) for name in ('baseline.json','current.json','restart.json')]
r=docs[0]['frames'][0]['report']; node=r['receipt']['node_id']
inventory={'schema_version':1,'accounts':[{'account_id':'a','plan':'trial'},{'account_id':'b','plan':'paid'}],
'meters':[{'id':a,'account_id':a,'node_id':node,'meter_id':u['grant_id'],'source':'panel','measurement_point':'client_ingress'}
for a,u in zip(('a','b'),r['usage'])]}
initialize(root/'observer.db',inventory,timestamp(r['observed_at']))
with Observer(root/'observer.db') as s:
  for i,d in enumerate(docs):
    at=timestamp(d['frames'][0]['report']['observed_at'])
    rows=convert_frames(d,s.meters()); out=s.observe(rows,at)
    if i==1:
      assert len(out['report']['events'])==1
      a,b=out['report']['accounts']
      assert a['download_lower_bytes']==20_000_000_000 and a['shadow_state']=='active'
      assert b['download_lower_bytes']==49_000_000_000 and b['shadow_state']=='none'
      assert s.observe(rows,at)['import']=={'inserted':0,'replayed':2}
    if i==2:
      assert all('epoch_changed' in a['quality_reasons'] for a in out['report']['accounts'])
      assert all(a['download_upper_bytes'] is None for a in out['report']['accounts'])
print('panel_export_observer_pass')
`
	cmd := exec.Command(python, "-c", script, dir)
	cmd.Dir = filepath.Join("..", "..", "..")
	out, e := cmd.CombinedOutput()
	if e != nil || !bytes.Contains(out, []byte("panel_export_observer_pass")) {
		t.Fatalf("local bridge failed: %v %s", e, out)
	}
	// Exercise the actual CLI against this exact disposable schema as well.
	cliDir := t.TempDir()
	if e = os.Chmod(cliDir, 0700); e != nil {
		t.Fatal(e)
	}
	idsFile := filepath.Join(cliDir, "nodes.json")
	idsJSON, _ := json.Marshal([]string{n.ID})
	if e = os.WriteFile(idsFile, idsJSON, 0600); e != nil {
		t.Fatal(e)
	}
	dsnFile := filepath.Join(cliDir, "database-url")
	if e = os.WriteFile(dsnFile, []byte(os.Getenv("PANEL_TEST_DATABASE_URL")), 0600); e != nil {
		t.Fatal(e)
	}
	repo, e := filepath.Abs(filepath.Join("..", "..", ".."))
	if e != nil {
		t.Fatal(e)
	}
	cliContext, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cli := exec.CommandContext(cliContext, filepath.Join(repo, "mobile", "scripts", "go.sh"),
		"run", "-mod=readonly", "./cmd/panelctl", "export-traffic", "--nodes-file", idsFile, "--output-dir", cliDir)
	cli.Dir = filepath.Join(repo, "panel")
	cli.Env = append(os.Environ(), "PANEL_DATABASE_URL_FILE="+dsnFile,
		"PANEL_ALLOW_LOCAL_DB_PLAINTEXT=1",
		"PGOPTIONS=-c search_path="+cfg.ConnConfig.RuntimeParams["search_path"]+" -c default_transaction_read_only=on",
		"GOPROXY=off", "GOSUMDB=off")
	out, e = cli.CombinedOutput()
	if e != nil || strings.TrimSpace(string(out)) != "traffic_snapshot_exported_observation_only" {
		t.Fatalf("local exporter CLI failed: %v %s", e, out)
	}
	cliRaw, e := os.ReadFile(filepath.Join(cliDir, trafficexport.SnapshotName))
	expected, readErr := os.ReadFile(filepath.Join(dir, "restart.json"))
	if e != nil || readErr != nil || !bytes.Equal(cliRaw, expected) {
		t.Fatal("CLI publication differs from stored report")
	}
	if _, e = f.p.Exec(ctx, "UPDATE nodes_registry SET state='revoked' WHERE id=$1", n.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = trafficexport.Read(ctx, reader, []string{n.ID}); !errors.Is(e, trafficexport.ErrNotCurrent) {
		t.Fatal(e)
	}
	// Assert output is valid typed JSON, not engine/policy/config material.
	var doc trafficexport.Document
	if json.Unmarshal(current, &doc) != nil || len(doc.Frames) != 1 {
		t.Fatal("invalid envelope")
	}
}
