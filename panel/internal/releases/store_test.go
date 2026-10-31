package releases

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"os"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/secrets"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	t                         *testing.T
	s                         *Store
	actor, user, device, cred string
	r                         Recipe
	n                         int
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := dbtest.New(t)
	v, _ := secrets.New(bytes.Repeat([]byte{17}, 32))
	s := New(p, v, nodes.New(p, v, nil))
	f := &fixture{t: t, s: s}
	f.actor, _ = database.NewID()
	f.user, _ = database.NewID()
	f.device, _ = database.NewID()
	f.cred, _ = database.NewID()
	ent, _ := database.NewID()
	cipher, _ := v.Seal(bytes.Repeat([]byte{19}, 32), access.CredentialAAD(f.user, f.device, f.cred, 1))
	ctx := context.Background()
	tx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer database.Rollback(tx)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO access_users(id,name) VALUES($1,'Release test')", []any{f.user}},
		{"INSERT INTO access_entitlements(id,user_id,state,expires_at,device_limit,group_id,revision) VALUES($1,$2,'active',clock_timestamp()+interval '2 days',2,$3,1)", []any{ent, f.user, access.DefaultGroupID}},
		{"INSERT INTO access_devices(id,user_id,name,state,public_key) VALUES($1,$2,'Phone test','registered',$3)", []any{f.device, f.user, bytes.Repeat([]byte{20}, 32)}},
		{"INSERT INTO access_credentials(id,user_id,device_id,version,state,ciphertext) VALUES($1,$2,$3,1,'active',$4)", []any{f.cred, f.user, f.device, cipher}},
	} {
		if _, e = tx.Exec(ctx, q.sql, q.args...); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile("../../tests/compatibility/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &fixtures)
	prep, e := s.Catalog.Prepare(ctx, catalog.Input{Name: "Accepted source", Kind: "upload", Input: string(fixtures.Cases[0].Expected)})
	if e != nil {
		t.Fatal(e)
	}
	draft, e := s.Catalog.DraftTx(ctx, tx, f.actor, prep)
	if e != nil {
		t.Fatal(e)
	}
	source, _, e := s.Catalog.MutateTx(ctx, tx, catalog.Mutation{Actor: f.actor, Key: "fixture-source-create-001", Operation: "create", DraftID: draft.ID})
	if e != nil {
		t.Fatal(e)
	}
	f.r = Recipe{SourceID: source.ID, VersionID: source.Current.ID, ExternalCredentials: true, MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}, NodeIDs: []string{}}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) mutation(op string, d Detail) Mutation {
	f.n++
	return Mutation{Actor: f.actor, Key: fmt.Sprintf("release-test-key-%06d", f.n), Operation: op, UserID: f.user, DeviceID: f.device, Revision: d.Subscription.Revision, TokenRevision: d.Subscription.TokenRevision}
}
func (f *fixture) run(m Mutation) (Detail, bool, error) {
	ctx := context.Background()
	tx, e := f.s.Pool.Begin(ctx)
	if e != nil {
		return Detail{}, false, e
	}
	defer database.Rollback(tx)
	d, r, e := f.s.MutateTx(ctx, tx, m)
	if e == nil {
		e = tx.Commit(ctx)
	}
	return d, r, e
}
func (f *fixture) must(m Mutation) Detail {
	f.t.Helper()
	d, _, e := f.run(m)
	if e != nil {
		f.t.Fatal(m.Operation, e)
	}
	return d
}
func (f *fixture) stage(d Detail) Detail {
	m := f.mutation("stage", d)
	m.Recipe = &f.r
	return f.must(m)
}
func (f *fixture) publish(d Detail) Detail {
	m := f.mutation("publish", d)
	m.ReleaseID = d.Releases[0].ID
	return f.must(m)
}
func (f *fixture) token() string {
	f.t.Helper()
	ctx := context.Background()
	tx, e := f.s.Pool.Begin(ctx)
	if e != nil {
		f.t.Fatal(e)
	}
	defer database.Rollback(tx)
	token, e := f.s.LinkTx(ctx, tx, f.actor, f.user, f.device)
	if e != nil {
		f.t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		f.t.Fatal(e)
	}
	return token
}
func TestStableLinkUpdateRollbackAndRevocation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	d := f.stage(Detail{})
	m := f.mutation("publish", d)
	m.ReleaseID = d.Releases[0].ID
	d = f.must(m)
	retry, replayed, e := f.run(m)
	if e != nil || !replayed || retry.Subscription.Revision != d.Subscription.Revision {
		t.Fatal("lost ACK")
	}
	d = f.must(f.mutation("rotate", d))
	token := f.token()
	first, e := f.s.Delivery(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	d = f.publish(f.stage(d))
	second, e := f.s.Delivery(ctx, token)
	if e != nil || bytes.Equal(first.Body, second.Body) {
		t.Fatal("stable URL did not update")
	}
	m = f.mutation("rollback", d)
	m.ReleaseID = d.Releases[1].ID
	d = f.publish(f.must(m))
	if d.Releases[0].Number != 3 {
		t.Fatal("rollback not monotonic")
	}
	if _, e = f.s.Delivery(ctx, token); e != nil {
		t.Fatal("rollback lost link")
	}
	d = f.must(f.mutation("rotate", d))
	if _, e = f.s.Delivery(ctx, token); e == nil {
		t.Fatal("old token survived rotation")
	}
	token = f.token()
	d = f.must(f.mutation("revoke", d))
	if _, e = f.s.Delivery(ctx, token); e == nil {
		t.Fatal("revoked token")
	}
	// Independent token lifecycle never changes the VPN credential.
	var id string
	f.s.Pool.QueryRow(ctx, "SELECT id::text FROM access_credentials WHERE device_id=$1 AND state='active'", f.device).Scan(&id)
	if id != f.cred {
		t.Fatal("token rotation changed VPN key")
	}
	if _, e = f.s.Pool.Exec(ctx, "UPDATE subscription_releases SET digest=repeat('0',64)"); e == nil {
		t.Fatal("mutable release")
	}
}
func TestRightsChangeBetweenStagePublishAndRollback(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	d := f.publish(f.stage(Detail{}))
	d = f.must(f.mutation("rotate", d))
	token := f.token()
	d = f.stage(d)
	if _, e := f.s.Pool.Exec(ctx, "UPDATE access_users SET state='suspended',revision=revision+1,policy_epoch=policy_epoch+1 WHERE id=$1", f.user); e != nil {
		t.Fatal(e)
	}
	for _, op := range []string{"publish", "rollback"} {
		m := f.mutation(op, d)
		m.ReleaseID = d.Releases[0].ID
		if _, _, e := f.run(m); e == nil {
			t.Fatal("restored denied access", op)
		}
	}
	if _, e := f.s.Delivery(ctx, token); e == nil {
		t.Fatal("delivered blocked user")
	}
	if _, e := f.s.Pool.Exec(ctx, "UPDATE access_users SET state='active',revision=revision+1,policy_epoch=policy_epoch+1 WHERE id=$1", f.user); e != nil {
		t.Fatal(e)
	}
	m := f.mutation("publish", d)
	m.ReleaseID = d.Releases[0].ID
	if _, _, e := f.run(m); e != ErrConflict {
		t.Fatal("stale epoch published", e)
	}
}
func TestPublishRaceAndExpiryAndNoPlaintextPersistence(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	d := f.stage(Detail{})
	m := f.mutation("publish", d)
	m.ReleaseID = d.Releases[0].ID
	other := m
	other.Key = "concurrent-publish-different-key"
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, input := range []Mutation{m, other} {
		wg.Add(1)
		go func(in Mutation) { defer wg.Done(); _, _, e := f.run(in); errs <- e }(input)
	}
	wg.Wait()
	close(errs)
	success := 0
	for e := range errs {
		if e == nil {
			success++
		} else if e != ErrConflict {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal("CAS race")
	}
	tx, _ := f.s.Pool.Begin(ctx)
	d, _ = f.s.DetailTx(ctx, tx, f.user, f.device)
	tx.Rollback(ctx)
	d = f.must(f.mutation("rotate", d))
	token := f.token()
	var stored string
	f.s.Pool.QueryRow(ctx, "SELECT string_agg(result::text,'') FROM subscription_mutations").Scan(&stored)
	if strings.Contains(stored, token) || strings.Contains(stored, "settings") {
		t.Fatal("secret projection")
	}
	f.s.Pool.Exec(ctx, "UPDATE access_entitlements SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1", f.user)
	if _, e := f.s.Delivery(ctx, token); e == nil {
		t.Fatal("expired delivery")
	}
}
func TestLeaseRenewsWithCurrentEntitlement(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	d := f.publish(f.stage(Detail{}))
	d = f.must(f.mutation("rotate", d))
	token := f.token()
	first, e := f.s.Delivery(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	f.s.Pool.Exec(ctx, "UPDATE access_entitlements SET expires_at=clock_timestamp()+interval '3 days',revision=revision+1 WHERE user_id=$1", f.user)
	second, e := f.s.Delivery(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(first.Body, second.Body) || !bytes.Equal(policyBytes(first.Body), policyBytes(second.Body)) {
		t.Fatal("metadata renewal changed policy or missing expiry")
	}
	var a, b map[string]any
	json.Unmarshal(first.Body, &a)
	json.Unmarshal(second.Body, &b)
	if a["revision"] != b["revision"] {
		t.Fatal("metadata-only change bumped config")
	}
}

func TestPartialRolloutKeepsWholePreviousAssignment(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	d := f.publish(f.stage(Detail{}))
	old := *d.Subscription.ActiveRelease
	node, _ := database.NewID()
	installation, _ := database.NewID()
	if _, e := f.s.Pool.Exec(ctx, "INSERT INTO nodes_registry(id,name) VALUES($1,'Unready required node')", node); e != nil {
		t.Fatal(e)
	}
	endpoint, _ := json.Marshal(nodes.VPNEndpoint{Host: "vpn.example.com", Port: 8443, ServerName: "vpn.example.com"})
	if _, e := f.s.Pool.Exec(ctx, "INSERT INTO nodes_vpn_installations(node_id,installation_id,group_id,enabled,endpoint) VALUES($1,$2,$3,true,$4)", node, installation, access.DefaultGroupID, endpoint); e != nil {
		t.Fatal(e)
	}
	f.r.NodeIDs = []string{node}
	d = f.stage(d)
	d = f.publish(d)
	if d.Releases[0].State != "partial" || d.Subscription.ActiveRelease == nil || *d.Subscription.ActiveRelease != old || len(d.Releases[0].Checks) != 1 || d.Releases[0].Checks[0].State == "healthy" {
		t.Fatal("partial rollout switched assignment")
	}
	// Changing endpoint after staging cannot silently replace the reviewed artifact.
	endpoint, _ = json.Marshal(nodes.VPNEndpoint{Host: "changed.example.com", Port: 8443, ServerName: "changed.example.com"})
	f.s.Pool.Exec(ctx, "UPDATE nodes_vpn_installations SET endpoint=$2 WHERE node_id=$1", node, endpoint)
	m := f.mutation("publish", d)
	m.ReleaseID = d.Releases[0].ID
	if _, _, e := f.run(m); e != ErrConflict {
		t.Fatal("endpoint drift accepted", e)
	}
}
func TestRotatedCredentialCannotBeDeliveredOrResurrected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	d := f.publish(f.stage(Detail{}))
	d = f.must(f.mutation("rotate", d))
	token := f.token()
	f.s.Pool.Exec(ctx, "UPDATE access_credentials SET state='revoked' WHERE id=$1", f.cred)
	if _, e := f.s.Delivery(ctx, token); e == nil {
		t.Fatal("revoked credential delivered")
	}
	m := f.mutation("rollback", d)
	m.ReleaseID = d.Releases[0].ID
	if _, _, e := f.run(m); e == nil {
		t.Fatal("rollback resurrected credential")
	}
}

func TestRollbackRefusesChangedNodeBinding(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	node, _ := database.NewID()
	installation, _ := database.NewID()
	f.s.Pool.Exec(ctx, "INSERT INTO nodes_registry(id,name) VALUES($1,'Binding test')", node)
	endpoint, _ := json.Marshal(nodes.VPNEndpoint{Host: "vpn.example.com", Port: 8443, ServerName: "vpn.example.com"})
	f.s.Pool.Exec(ctx, "INSERT INTO nodes_vpn_installations(node_id,installation_id,group_id,enabled,endpoint) VALUES($1,$2,$3,true,$4)", node, installation, access.DefaultGroupID, endpoint)
	f.r.NodeIDs = []string{node}
	d := f.stage(Detail{})
	endpoint, _ = json.Marshal(nodes.VPNEndpoint{Host: "changed.example.com", Port: 8443, ServerName: "changed.example.com"})
	f.s.Pool.Exec(ctx, "UPDATE nodes_vpn_installations SET endpoint=$2 WHERE node_id=$1", node, endpoint)
	m := f.mutation("rollback", d)
	m.ReleaseID = d.Releases[0].ID
	if _, _, e := f.run(m); e != ErrConflict {
		t.Fatal("rollback mixed old source and new endpoint", e)
	}
}

func TestMultipleAcceptedVersionsAreFrozenAndDeliveredTogether(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	tx, e := f.s.Pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer database.Rollback(tx)
	frozen, e := f.s.Catalog.FrozenTx(ctx, tx, f.r.SourceID, f.r.VersionID, false, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := f.s.Catalog.Prepare(ctx, catalog.Input{Name: "Second accepted source", Kind: "upload", Input: string(frozen.Normalized)})
	if e != nil {
		t.Fatal(e)
	}
	draft, e := f.s.Catalog.DraftTx(ctx, tx, f.actor, prepared)
	if e != nil {
		t.Fatal(e)
	}
	second, _, e := f.s.Catalog.MutateTx(ctx, tx, catalog.Mutation{Actor: f.actor, Key: "second-source-key-000001", Operation: "create", DraftID: draft.ID})
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	f.r.Sources = []SourceRef{{ID: f.r.SourceID, VersionID: f.r.VersionID}, {ID: second.ID, VersionID: second.Current.ID}}
	f.r.SourceID = ""
	f.r.VersionID = ""
	d := f.publish(f.stage(Detail{}))
	d = f.must(f.mutation("rotate", d))
	artifact, e := f.s.Delivery(ctx, f.token())
	if e != nil || len(artifact.Preview.Profiles) != 10 {
		t.Fatal("multi-source issuance", e)
	}
	var provenance struct {
		Sources []SourceRef `json:"sources"`
	}
	if json.Unmarshal(d.Releases[0].Provenance, &provenance) != nil || len(provenance.Sources) != 2 {
		t.Fatal("source revision provenance missing")
	}
}

func TestLeaseRefreshHasDurableMonotonicWireRevision(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	d := f.publish(f.stage(Detail{}))
	d = f.must(f.mutation("rotate", d))
	token := f.token()
	_, e := f.s.Delivery(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Pool.Exec(ctx, "UPDATE subscription_delivery SET valid_until=clock_timestamp()+interval '13 hours',revision=revision+1 WHERE subscription_id=$1", d.Subscription.ID); e != nil {
		t.Fatal(e)
	}
	first, e := f.s.Delivery(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	again, e := f.s.Delivery(ctx, token)
	if e != nil || !bytes.Equal(first.Body, again.Body) {
		t.Fatal("ordinary refresh changed fingerprint under same revision")
	}
	// Model a lease nearing expiry without changing wall clock or user rights.
	if _, e = f.s.Pool.Exec(ctx, "UPDATE subscription_delivery SET valid_until=clock_timestamp()+interval '10 minutes' WHERE subscription_id=$1", d.Subscription.ID); e != nil {
		t.Fatal(e)
	}
	renewed, e := f.s.Delivery(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	if !renewed.Preview.ValidUntil.After(*first.Preview.ValidUntil) {
		t.Fatal("lease did not renew")
	}
	var a, b map[string]any
	json.Unmarshal(first.Body, &a)
	json.Unmarshal(renewed.Body, &b)
	if b["revision"].(float64) <= a["revision"].(float64) {
		t.Fatal("lease renewal kept stale wire revision")
	}
	stable, e := f.s.Delivery(ctx, token)
	if e != nil || !bytes.Equal(stable.Body, renewed.Body) {
		t.Fatal("renewal was not persisted")
	}
	// A fresh store/process instance reads the same wire snapshot.
	fresh := New(f.s.Pool, f.s.Vault, f.s.Nodes)
	stable, e = fresh.Delivery(ctx, token)
	if e != nil || !bytes.Equal(stable.Body, renewed.Body) {
		t.Fatal("restart lost delivery revision")
	}
}
