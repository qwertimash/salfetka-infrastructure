package subscriptionsets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/releases"
)

type person struct {
	user, device, cred string
	key                ed25519.PrivateKey
}
type pubFixture struct {
	s           *Store
	p           *pgxpool.Pool
	engine      *releases.Store
	actor, node string
	people      []person
	doc         builder.Document
}

func (f *pubFixture) person(t *testing.T, user string) person {
	t.Helper()
	if user == "" {
		user = id(t)
		if _, e := f.p.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,'Publication account')", user); e != nil {
			t.Fatal(e)
		}
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	a := person{user: user, device: id(t), cred: id(t), key: key}
	cipher, e := f.s.Builder.Vault.Seal(bytes.Repeat([]byte{27}, 32), access.CredentialAAD(user, a.device, a.cred, 1))
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO access_entitlements(id,user_id,state,expires_at,device_limit,group_id,revision) VALUES($1,$2,'active',clock_timestamp()+interval '2 days',5,$3,1) ON CONFLICT(user_id) DO NOTHING", []any{id(t), user, access.DefaultGroupID}},
		{"INSERT INTO access_devices(id,user_id,name,state,public_key) VALUES($1,$2,'Physical fixture','registered',$3)", []any{a.device, user, pub}},
		{"INSERT INTO access_credentials(id,user_id,device_id,version,state,ciphertext) VALUES($1,$2,$3,1,'active',$4)", []any{a.cred, user, a.device, cipher}},
	} {
		if _, e = f.p.Exec(ctx, q.sql, q.args...); e != nil {
			t.Fatal(e)
		}
	}
	f.people = append(f.people, a)
	return a
}
func publicationFixture(t *testing.T) *pubFixture {
	t.Helper()
	s, p, user, actor := fixture(t)
	f := &pubFixture{s: s, p: p, actor: actor, node: id(t)}
	f.engine = releases.New(p, s.Builder.Vault, nodes.New(p, s.Builder.Vault, nil))
	f.person(t, user)
	f.person(t, "")
	endpoint, _ := json.Marshal(nodes.VPNEndpoint{Host: "vpn.example.com", Port: 8443, ServerName: "vpn.example.com"})
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO nodes_registry(id,name,state,serial,public_key,certificate_expires_at) VALUES($1,'Synthetic healthy node','active','test-serial',$2,clock_timestamp()+interval '1 day')", []any{f.node, bytes.Repeat([]byte{21}, 32)}},
		{"INSERT INTO nodes_vpn_installations(node_id,installation_id,group_id,enabled,endpoint,generation,engine_epoch,projection_sha256,policy_expires_at) VALUES($1,$2,$3,true,$4,1,repeat('a',32),repeat('b',64),clock_timestamp()+interval '5 minutes')", []any{f.node, id(t), access.DefaultGroupID, endpoint}},
		{"INSERT INTO nodes_vpn_policies(node_id,generation,engine_epoch,policy_ciphertext,policy_sha256,issued_at,expires_at) VALUES($1,1,repeat('a',32),$2,repeat('c',64),clock_timestamp(),clock_timestamp()+interval '4 minutes')", []any{f.node, bytes.Repeat([]byte{22}, 64)}},
		{"INSERT INTO nodes_vpn_receipts(node_id,generation,body,body_sha256) VALUES($1,1,'{}',$2)", []any{f.node, bytes.Repeat([]byte{23}, 32)}},
	} {
		if _, e := p.Exec(ctx, q.sql, q.args...); e != nil {
			t.Fatal(e)
		}
	}
	f.observe(t)
	f.doc = document("Основная подписка")
	f.doc.Recipe.NodeIDs = []string{f.node}
	f.doc.Recipe.Blueprint = &compiler.Blueprint{Version: 1, Network: compiler.PolicyChoice{Authority: "custom", Value: json.RawMessage(`{"dns_servers":["1.1.1.1"],"probe":{"url":"https://probe.example.invalid/generate_204","expected_status":204,"ipv4":"198.51.100.10","body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}`)}, Routing: map[string]compiler.PolicyChoice{"vpn": {Authority: "personal"}}, Locations: []compiler.Location{{ID: "location-main", Title: "Germany", Country: "DE", Mode: "vpn", Kind: "location", Selection: "first_working", Members: []compiler.Member{{NodeID: f.node}}}}}
	return f
}
func (f *pubFixture) observe(t *testing.T) {
	t.Helper()
	usage := []nodewire.VPNUsage{}
	for _, p := range f.people {
		usage = append(usage, nodewire.VPNUsage{GrantID: p.cred, Active: true})
	}
	body, _ := json.Marshal(nodewire.VPNReport{Receipt: nodewire.VPNReceipt{Generation: 1}, EngineEpoch: strings.Repeat("a", 32), Sequence: 1, ObservedAt: time.Now().UTC(), Usage: usage})
	_, e := f.p.Exec(ctx, "INSERT INTO nodes_vpn_observations(node_id,generation,engine_epoch,sequence,body,body_sha256) VALUES($1,1,repeat('a',32),1,$2,$3) ON CONFLICT(node_id) DO UPDATE SET body=excluded.body,received_at=clock_timestamp()", f.node, string(body), bytes.Repeat([]byte{24}, 32))
	if e != nil {
		t.Fatal(e)
	}
}
func (f *pubFixture) set(t *testing.T, key string) Set {
	t.Helper()
	v, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: key, Document: f.doc})
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f *pubFixture) assign(t *testing.T, set Set, p person, key string) Assignment {
	t.Helper()
	a, _, e := assign(f.p, f.s, Assign{Actor: f.actor, Key: key, UserID: p.user, SetID: set.ID, State: "active"})
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func (f *pubFixture) publish(t *testing.T, set Set, key string) Publication {
	t.Helper()
	out, _, e := transact(f.p, func(tx pgx.Tx) (Publication, bool, error) {
		return f.s.PublishTx(ctx, tx, Publish{Actor: f.actor, Key: key, ID: set.ID, Revision: set.Revision})
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func (f *pubFixture) drain(t *testing.T) {
	t.Helper()
	f.observe(t)
	if _, e := f.s.ScanTargets(ctx); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 30; i++ {
		worked, e := f.s.RunOne(ctx, f.engine)
		if e != nil {
			t.Fatal(e)
		}
		if !worked {
			return
		}
	}
	t.Fatal("queue did not drain")
}
func (f *pubFixture) status(t *testing.T, pub Publication) Publication {
	t.Helper()
	tx, _ := f.p.Begin(ctx)
	defer database.Rollback(tx)
	p, e := f.s.PublicationTx(ctx, tx, pub.ID)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func (f *pubFixture) link(t *testing.T, a Assignment, p person) string {
	t.Helper()
	tx, _ := f.p.Begin(ctx)
	defer database.Rollback(tx)
	link, e := f.s.DeviceLinkTx(ctx, tx, f.engine, f.actor, a.ID, p.device)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return link
}
func (f *pubFixture) accountLink(t *testing.T, a Assignment) string {
	t.Helper()
	tx, _ := f.p.Begin(ctx)
	defer database.Rollback(tx)
	link, e := f.s.AssignmentLinkTx(ctx, tx, f.actor, a.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return link
}
func TestPublicationUpdatesAllUsersStableLinksAndIndependentSets(t *testing.T) {
	f := publicationFixture(t)
	set := f.set(t, "pub-create-set-0001")
	a := f.assign(t, set, f.people[0], "pub-assign-user-a-001")
	b := f.assign(t, set, f.people[1], "pub-assign-user-b-001")
	pub := f.publish(t, set, "pub-version-one-0001")
	f.drain(t)
	if got := f.status(t, pub); got.Published != 2 || got.Retry != 0 {
		t.Fatalf("publication not applied: %+v", got)
	}
	la, lb := f.link(t, a, f.people[0]), f.link(t, b, f.people[1])
	accountLink := f.accountLink(t, a)
	first, e := f.engine.Delivery(ctx, la)
	if e != nil {
		t.Fatal(e)
	}
	other, e := f.engine.Delivery(ctx, lb)
	if e != nil {
		t.Fatal(e)
	}
	if manifestCredential(t, first.Body) == manifestCredential(t, other.Body) {
		t.Fatal("shared account artifact")
	}
	// A second set on the SAME physical device must get a separate URL.
	second := f.set(t, "pub-second-set-0001")
	a2 := f.assign(t, second, f.people[0], "pub-second-assign-001")
	f.publish(t, second, "pub-second-publish-001")
	f.drain(t)
	secondLink := f.link(t, a2, f.people[0])
	if secondLink == la {
		t.Fatal("same link for distinct subscriptions")
	}
	f.doc.Recipe.Blueprint.Locations[0].Title = "Germany updated"
	changed, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: "pub-save-version-two", ID: set.ID, Revision: 1, Document: f.doc})
	if e != nil {
		t.Fatal(e)
	}
	unchanged, e := f.engine.Delivery(ctx, la)
	if e != nil || !bytes.Equal(first.Body, unchanged.Body) {
		t.Fatal("save published implicitly", e)
	}
	pub2 := f.publish(t, changed, "pub-version-two-0001")
	f.drain(t)
	if got := f.status(t, pub2); got.Published != 2 {
		t.Fatal(got)
	}
	if f.link(t, a, f.people[0]) != la || f.link(t, b, f.people[1]) != lb || f.accountLink(t, a) != accountLink {
		t.Fatal("publication rotated stable links")
	}
	for _, link := range []string{la, lb} {
		body, e := f.engine.Delivery(ctx, link)
		if e != nil || !bytes.Contains(body.Body, []byte("Germany updated")) {
			t.Fatal("missing new release", e)
		}
	}
	body, e := f.engine.Delivery(ctx, secondLink)
	if e != nil || bytes.Contains(body.Body, []byte("Germany updated")) {
		t.Fatal("unrelated set changed", e)
	}
	// A late account and another confirmed device join the existing publication.
	c := f.person(t, "")
	f.assign(t, changed, c, "pub-late-assignment-001")
	extra := f.person(t, f.people[0].user)
	f.drain(t)
	extraBody, err := f.engine.Delivery(ctx, f.link(t, a, extra))
	if err != nil {
		t.Fatal(err)
	}
	if manifestCredential(t, first.Body) == manifestCredential(t, extraBody.Body) {
		t.Fatal("two physical devices share a credential")
	}
	if got := f.status(t, pub2); got.Published != 4 {
		t.Fatal("late targets absent", got)
	}
}
func TestPublicationFailurePreservesGoodReleaseAndRecovers(t *testing.T) {
	f := publicationFixture(t)
	set := f.set(t, "failure-create-set-001")
	a := f.assign(t, set, f.people[0], "failure-assign-set-01")
	f.publish(t, set, "failure-publish-good")
	f.drain(t)
	link := f.link(t, a, f.people[0])
	before, _ := f.engine.Delivery(ctx, link)
	// Invalid draft remains editable but cannot replace the last compiled release.
	bad := f.doc
	bad.Recipe.Blueprint = &compiler.Blueprint{Version: 1}
	changed, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: "failure-invalid-save", ID: set.ID, Revision: 1, Document: bad})
	if e != nil {
		t.Fatal(e)
	}
	pub := f.publish(t, changed, "failure-invalid-publish")
	f.drain(t)
	if got := f.status(t, pub); got.Retry != 1 || got.Published != 0 {
		t.Fatal(got)
	}
	after, e := f.engine.Delivery(ctx, link)
	if e != nil || !bytes.Equal(before.Body, after.Body) {
		t.Fatal("lost good artifact", e)
	}
	var n int
	f.p.QueryRow(ctx, "SELECT count(*) FROM subscription_releases").Scan(&n)
	if n != 1 {
		t.Fatal("failed savepoint leaked release", n)
	}
	fixed, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: "failure-fixed-save-01", ID: set.ID, Revision: 2, Document: f.doc})
	if e != nil {
		t.Fatal(e)
	}
	next := f.publish(t, fixed, "failure-fixed-publish")
	f.drain(t)
	if got := f.status(t, next); got.Published != 1 {
		t.Fatal(got)
	}
}
func TestAssignmentProofRevocationReassignmentAndAccountBlock(t *testing.T) {
	f := publicationFixture(t)
	set := f.set(t, "proof-create-set-0001")
	a := f.assign(t, set, f.people[0], "proof-assign-a-000001")
	b := f.assign(t, set, f.people[1], "proof-assign-b-000001")
	f.publish(t, set, "proof-publish-set-001")
	f.drain(t)
	token := f.accountLink(t, a)
	la, lb := f.link(t, a, f.people[0]), f.link(t, b, f.people[1])
	person := f.people[0]
	proof := DeviceProof{DeviceID: person.device, IssuedAt: time.Now().Unix()}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(person.key, []byte(ProofMessage(token, proof.DeviceID, proof.IssuedAt))))
	for i := 0; i < 2; i++ {
		resolved, e := f.s.Resolve(ctx, f.engine, token, proof)
		if e != nil || resolved != la {
			t.Fatal("proof replay/read", e)
		}
	}
	wrong := proof
	wrong.DeviceID = f.people[1].device
	if _, e := f.s.Resolve(ctx, f.engine, token, wrong); !errors.Is(e, releases.ErrDenied) {
		t.Fatal("foreign device accepted", e)
	}
	stale := proof
	stale.IssuedAt -= 120
	stale.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(person.key, []byte(ProofMessage(token, stale.DeviceID, stale.IssuedAt))))
	if _, e := f.s.Resolve(ctx, f.engine, token, stale); !errors.Is(e, releases.ErrDenied) {
		t.Fatal("stale proof", e)
	}
	// Revoke while a newly published target is still queued.
	revised, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: "proof-version-two-01", ID: set.ID, Revision: 1, Document: f.doc})
	if e != nil {
		t.Fatal(e)
	}
	f.publish(t, revised, "proof-publish-two-001")
	if _, e = f.s.ScanTargets(ctx); e != nil {
		t.Fatal(e)
	}
	removed, _, e := assign(f.p, f.s, Assign{Actor: f.actor, Key: "proof-revoke-a-00001", UserID: a.UserID, SetID: a.SetID, Revision: 1, State: "revoked"})
	if e != nil {
		t.Fatal(e)
	}
	f.drain(t)
	if _, e = f.engine.Delivery(ctx, la); !errors.Is(e, releases.ErrDenied) {
		t.Fatal("revoked delivery", e)
	}
	if _, e = f.s.Resolve(ctx, f.engine, token, proof); !errors.Is(e, releases.ErrDenied) {
		t.Fatal("revoked account link", e)
	}
	if _, e = f.engine.Delivery(ctx, lb); e != nil {
		t.Fatal("B interrupted", e)
	}
	again, _, e := assign(f.p, f.s, Assign{Actor: f.actor, Key: "proof-reassign-a-001", UserID: a.UserID, SetID: a.SetID, Revision: removed.Revision, State: "active"})
	if e != nil {
		t.Fatal(e)
	}
	f.drain(t)
	if f.link(t, again, person) == la || f.accountLink(t, again) == token {
		t.Fatal("old generation revived")
	}
	if _, e = f.engine.Delivery(ctx, la); !errors.Is(e, releases.ErrDenied) {
		t.Fatal("old URL revived", e)
	}
	if _, e = f.p.Exec(ctx, "UPDATE access_users SET state='suspended',revision=revision+1 WHERE id=$1", b.UserID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.engine.Delivery(ctx, lb); !errors.Is(e, releases.ErrDenied) {
		t.Fatal("blocked account delivery", e)
	}
}
func TestPublicationConcurrencyRollbackAndLostACK(t *testing.T) {
	f := publicationFixture(t)
	set := f.set(t, "concurrent-pub-create")
	f.assign(t, set, f.people[0], "concurrent-pub-assign")
	m := Publish{Actor: f.actor, Key: "concurrent-publish-01", ID: set.ID, Revision: 1}
	var wg sync.WaitGroup
	out := make(chan Publication, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, _, e := transact(f.p, func(tx pgx.Tx) (Publication, bool, error) { return f.s.PublishTx(ctx, tx, m) })
			if e != nil {
				t.Error(e)
			}
			out <- p
		}()
	}
	wg.Wait()
	one, two := <-out, <-out
	if one.ID != two.ID {
		t.Fatal("duplicate publication")
	}
	if _, e := f.s.ScanTargets(ctx); e != nil {
		t.Fatal(e)
	}
	// Simulate loss of the transaction before the worker's commit.
	tx, _ := f.p.Begin(ctx)
	defer database.Rollback(tx)
	nested, _ := tx.Begin(ctx)
	var assignment string
	var generation int64
	tx.QueryRow(ctx, "SELECT id::text,revision FROM account_set_assignments WHERE user_id=$1", f.people[0].user).Scan(&assignment, &generation)
	if e := f.s.applyTarget(ctx, nested, f.engine, one.ID, assignment, generation, f.people[0].user, f.people[0].device, f.actor, set.ID, 1, 0); e != nil {
		t.Fatal(e)
	}
	nested.Commit(ctx)
	database.Rollback(tx)
	fresh := &Store{Builder: builder.New(f.p, f.s.Builder.Vault)}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := fresh.RunOne(ctx, f.engine); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	var n int
	f.p.QueryRow(ctx, "SELECT count(*) FROM subscription_releases").Scan(&n)
	if n != 1 {
		t.Fatal("restart/parallel worker duplicated effects", n)
	}
	changed, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: "new-head-before-retry", ID: set.ID, Revision: 1, Document: f.doc})
	if e != nil {
		t.Fatal(e)
	}
	next := f.publish(t, changed, "new-head-publish-001")
	replay, yes, e := transact(f.p, func(tx pgx.Tx) (Publication, bool, error) { return f.s.PublishTx(ctx, tx, m) })
	if e != nil || !yes || replay.Current {
		t.Fatal("old publish replay moved pointer", e)
	}
	m.Key = fmt.Sprintf("new-key-stale-%s", next.ID)
	if _, _, e = transact(f.p, func(tx pgx.Tx) (Publication, bool, error) { return f.s.PublishTx(ctx, tx, m) }); !errors.Is(e, ErrConflict) {
		t.Fatal("stale publish", e)
	}
}

func TestPartialHealthRetriesOnlyFailedTarget(t *testing.T) {
	f := publicationFixture(t)
	set := f.set(t, "partial-health-create")
	a := f.assign(t, set, f.people[0], "partial-health-a-0001")
	b := f.assign(t, set, f.people[1], "partial-health-b-0001")
	f.publish(t, set, "partial-health-good-1")
	f.drain(t)
	la, lb := f.link(t, a, f.people[0]), f.link(t, b, f.people[1])
	before, _ := f.engine.Delivery(ctx, la)
	if !bytes.Contains(before.Body, []byte(f.doc.Title)) {
		t.Fatal("set title missing from manifest")
	}
	f.doc.Recipe.Blueprint.Locations[0].Title = "New target"
	set2, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: "partial-health-save-2", ID: set.ID, Revision: 1, Document: f.doc})
	if e != nil {
		t.Fatal(e)
	}
	pub := f.publish(t, set2, "partial-health-pub-2")
	report := nodewire.VPNReport{Receipt: nodewire.VPNReceipt{Generation: 1}, EngineEpoch: strings.Repeat("a", 32), Sequence: 2, ObservedAt: time.Now().UTC(), Usage: []nodewire.VPNUsage{{GrantID: f.people[1].cred, Active: true}}}
	body, _ := json.Marshal(report)
	if _, e = f.p.Exec(ctx, "UPDATE nodes_vpn_observations SET body=$1,received_at=clock_timestamp()", string(body)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ScanTargets(ctx); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = f.s.RunOne(ctx, f.engine); e != nil {
			t.Fatal(e)
		}
	}
	if got := f.status(t, pub); got.Published != 1 || got.Retry != 1 {
		t.Fatal("partial health hidden", got)
	}
	after, e := f.engine.Delivery(ctx, la)
	if e != nil || !bytes.Equal(before.Body, after.Body) {
		t.Fatal("unhealthy A lost good release", e)
	}
	updated, e := f.engine.Delivery(ctx, lb)
	if e != nil || !bytes.Contains(updated.Body, []byte("New target")) {
		t.Fatal("healthy B blocked by A", e)
	}
	tx, _ := f.p.Begin(ctx)
	page, e := f.s.TargetsTx(ctx, tx, pub.ID, "")
	database.Rollback(tx)
	if e != nil || len(page.Items) != 2 {
		t.Fatal(e)
	}
	var hasError bool
	for _, item := range page.Items {
		if item.State == "retry" && item.Code != "" {
			hasError = true
		}
	}
	if !hasError {
		t.Fatal("no safe target error exposed")
	}
	f.observe(t)
	if _, e = f.p.Exec(ctx, "UPDATE set_publication_targets SET next_attempt=clock_timestamp() WHERE state='retry'"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.RunOne(ctx, f.engine); e != nil {
		t.Fatal(e)
	}
	if got := f.status(t, pub); got.Published != 2 || got.Retry != 0 {
		t.Fatal("retry did not finish", got)
	}
	var n int
	f.p.QueryRow(ctx, "SELECT count(*) FROM subscription_releases").Scan(&n)
	if n != 4 {
		t.Fatal("retry recreated B release", n)
	}
}

func manifestCredential(t *testing.T, body []byte) string {
	t.Helper()
	var artifact struct {
		Connections []struct {
			Settings struct {
				Config struct {
					Outbounds []struct {
						Settings struct {
							VNext []struct {
								Users []struct {
									ID string `json:"id"`
								} `json:"users"`
							} `json:"vnext"`
						} `json:"settings"`
					} `json:"outbounds"`
				} `json:"xray_config"`
			} `json:"settings"`
		} `json:"connections"`
	}
	if json.Unmarshal(body, &artifact) != nil || len(artifact.Connections) != 1 {
		t.Fatal("missing personal config")
	}
	outbound := artifact.Connections[0].Settings.Config.Outbounds
	if len(outbound) == 0 || len(outbound[0].Settings.VNext) == 0 || len(outbound[0].Settings.VNext[0].Users) == 0 {
		t.Fatal("missing personal credential")
	}
	return outbound[0].Settings.VNext[0].Users[0].ID
}
func TestLegacyAndAssignedDeliveryCoexistOnSameDevice(t *testing.T) {
	f := publicationFixture(t)
	set := f.set(t, "legacy-scope-create-1")
	a := f.assign(t, set, f.people[0], "legacy-scope-assign-1")
	f.publish(t, set, "legacy-scope-publish1")
	f.drain(t)
	scopedLink := f.link(t, a, f.people[0])
	tx, _ := f.p.Begin(ctx)
	_, e := f.engine.DetailTx(ctx, tx, f.people[0].user, f.people[0].device)
	database.Rollback(tx)
	if !errors.Is(e, releases.ErrUnavailable) {
		t.Fatal("legacy lookup leaked assigned subscription", e)
	}
	var detail releases.Detail
	for i, operation := range []string{"stage", "publish", "rotate"} {
		m := releases.Mutation{Actor: f.actor, Key: fmt.Sprintf("legacy-scope-step-%04d", i), Operation: operation, UserID: f.people[0].user, DeviceID: f.people[0].device, Revision: detail.Subscription.Revision, TokenRevision: detail.Subscription.TokenRevision}
		if operation == "stage" {
			m.Recipe = &f.doc.Recipe
		}
		if operation == "publish" {
			m.ReleaseID = detail.Releases[0].ID
		}
		detail, _, e = transact(f.p, func(tx pgx.Tx) (releases.Detail, bool, error) { return f.engine.MutateTx(ctx, tx, m) })
		if e != nil {
			t.Fatal(e)
		}
	}
	tx, _ = f.p.Begin(ctx)
	legacyLink, e := f.engine.LinkTx(ctx, tx, f.actor, f.people[0].user, f.people[0].device)
	if e != nil {
		database.Rollback(tx)
		t.Fatal(e)
	}
	e = tx.Commit(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if legacyLink == scopedLink {
		t.Fatal("legacy and set token collision")
	}
	if _, e = f.engine.Delivery(ctx, legacyLink); e != nil {
		t.Fatal("legacy delivery", e)
	}
	if _, _, e = assign(f.p, f.s, Assign{Actor: f.actor, Key: "legacy-revoke-scoped", UserID: a.UserID, SetID: a.SetID, State: "revoked", Revision: 1}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.engine.Delivery(ctx, legacyLink); e != nil {
		t.Fatal("assignment revoke touched legacy", e)
	}
	if _, e = f.engine.Delivery(ctx, scopedLink); !errors.Is(e, releases.ErrDenied) {
		t.Fatal("assigned link survived revoke", e)
	}
}

func TestPublicationContinuesAfterHundredReleases(t *testing.T) {
	f := publicationFixture(t)
	set := f.set(t, "long-lived-set-create-001")
	a := f.assign(t, set, f.people[0], "long-lived-assign-00001")
	f.publish(t, set, "long-lived-publish-0001")
	f.drain(t)
	// Advance only this synthetic sequence: exercise the old boundary without
	// spending time building 100 identical fixtures.
	if _, e := f.p.Exec(ctx, "UPDATE subscriptions SET next_release=101 WHERE assignment_id=$1", a.ID); e != nil {
		t.Fatal(e)
	}
	f.doc.Title = "Updated long-lived set"
	next, _, e := save(f.p, f.s, Save{Actor: f.actor, Key: "long-lived-update-00001", ID: set.ID, Revision: set.Revision, Document: f.doc})
	if e != nil {
		t.Fatal(e)
	}
	pub := f.publish(t, next, "long-lived-publish-0002")
	f.drain(t)
	if state := f.status(t, pub); state.Published != 1 || state.Pending != 0 || state.Retry != 0 {
		t.Fatalf("publication: %+v", state)
	}
	var max int64
	if e = f.p.QueryRow(ctx, "SELECT max(r.number) FROM subscription_releases r JOIN subscriptions s ON s.id=r.subscription_id WHERE s.assignment_id=$1", a.ID).Scan(&max); e != nil {
		t.Fatal(e)
	}
	if max != 101 {
		t.Fatalf("release=%d", max)
	}
	if _, e = f.engine.Delivery(ctx, f.link(t, a, f.people[0])); e != nil {
		t.Fatal(e)
	}
}
