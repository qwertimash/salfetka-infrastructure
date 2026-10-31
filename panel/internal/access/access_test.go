package access

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/secrets"
	"salfetka/panel/migrations"
)

type accessFixture struct {
	t     *testing.T
	s     *Store
	p     *pgxpool.Pool
	actor string
	seq   int
}

func fixture(t *testing.T) *accessFixture {
	p := dbtest.New(t)
	key := make([]byte, 32)
	rand.Read(key)
	v, _ := secrets.New(key)
	id, _ := database.NewID()
	return &accessFixture{t: t, s: New(p, v), p: p, actor: id}
}
func (f *accessFixture) m(d Detail, route string) Mutation {
	f.seq++
	return Mutation{ActorID: f.actor, Route: route, TargetID: d.User.ID, Revision: d.User.Revision, Key: fmt.Sprintf("test-key-%08d", f.seq)}
}
func (f *accessFixture) tx(fn func(pgx.Tx) (Detail, bool, error)) (Detail, bool, error) {
	ctx := context.Background()
	tx, err := f.p.Begin(ctx)
	if err != nil {
		return Detail{}, false, err
	}
	defer database.Rollback(tx)
	d, replay, err := fn(tx)
	if err == nil {
		err = tx.Commit(ctx)
	}
	return d, replay, err
}
func (f *accessFixture) must(fn func(pgx.Tx) (Detail, bool, error)) Detail {
	f.t.Helper()
	d, _, err := f.tx(fn)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}
func (f *accessFixture) create(name string) Detail {
	m := f.m(Detail{}, "create")
	return f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.CreateTx(context.Background(), tx, m, name) })
}
func (f *accessFixture) entitlement(d Detail, action string, expiry time.Time, limit int) Detail {
	m := f.m(d, "entitlement")
	c := EntitlementChange{Action: action}
	if action == "set" || action == "restore" {
		g := DefaultGroupID
		c.ExpiresAt = &expiry
		c.DeviceLimit = &limit
		c.GroupID = &g
	} else if action == "renew" {
		c.ExpiresAt = &expiry
	}
	return f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.EntitlementTx(context.Background(), tx, m, c) })
}
func (f *accessFixture) read(id string) Detail {
	f.t.Helper()
	tx, err := f.p.Begin(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	defer database.Rollback(tx)
	d, err := f.s.DetailTx(context.Background(), tx, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}
func (f *accessFixture) challenge(d Detail, pub ed25519.PublicKey) (Challenge, error) {
	m := f.m(d, "challenge")
	tx, err := f.p.Begin(context.Background())
	if err != nil {
		return Challenge{}, err
	}
	defer database.Rollback(tx)
	c, _, err := f.s.ChallengeTx(context.Background(), tx, m, base64.RawURLEncoding.EncodeToString(pub))
	if err == nil {
		err = tx.Commit(context.Background())
	}
	return c, err
}
func (f *accessFixture) register(d Detail, c Challenge, priv ed25519.PrivateKey, name string) (Detail, error) {
	m := f.m(d, "register")
	r := Register{c.ID, base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(c.SigningMessage))), name}
	d, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.RegisterTx(context.Background(), tx, m, r) })
	return d, err
}
func (f *accessFixture) device(d Detail, name string) (Detail, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, err := f.challenge(d, pub)
	if err != nil {
		f.t.Fatal(err)
	}
	d = f.read(d.User.ID)
	d, err = f.register(d, c, priv, name)
	if err != nil {
		f.t.Fatal(err)
	}
	return d, priv
}
func TestEntitlementBlocksRefundAndExplicitRestore(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	d := f.create("Пользователь один")
	if d.Decision.Reason != "no_entitlement" || d.OutboxPending != 1 {
		t.Fatal("initial decision")
	}
	expires := time.Now().UTC().Add(time.Hour)
	d = f.entitlement(d, "set", expires, 2)
	entitlementID := d.Entitlement.ID
	if !database.ValidID(entitlementID) || entitlementID == d.User.ID {
		t.Fatal("independent entitlement identity")
	}
	d, _ = f.device(d, "Телефон один")
	if !d.Decision.Allowed || d.Decision.NodeState != "not_provisioned" {
		t.Fatal("logical grant")
	}
	m := f.m(d, "block")
	d = f.must(func(tx pgx.Tx) (Detail, bool, error) {
		return f.s.BlockTx(ctx, tx, m, BlockChange{Scope: "user", Reason: "policy"})
	})
	block := d.Blocks[0].ID
	d = f.entitlement(d, "renew", expires.Add(time.Hour), 0)
	if d.Decision.Allowed || d.Decision.Reason != "user_blocked" {
		t.Fatal("renew lifted policy")
	}
	d = f.entitlement(d, "refund", time.Time{}, 0)
	m = f.m(d, "late-renew")
	later := expires.Add(3 * time.Hour)
	_, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) {
		return f.s.EntitlementTx(ctx, tx, m, EntitlementChange{Action: "renew", ExpiresAt: &later})
	})
	if !errors.Is(err, ErrTerminal) {
		t.Fatal("late renewal revived refund", err)
	}
	d = f.entitlement(d, "restore", later, 2)
	if d.Entitlement.ID != entitlementID {
		t.Fatal("restore replaced entitlement identity")
	}
	if d.Decision.Allowed || d.Devices[0].Credential.State != "revoked" {
		t.Fatal("restore revived credentials or block")
	}
	m = f.m(d, "clear")
	d = f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.ClearBlockTx(ctx, tx, m, block) })
	if d.Decision.Allowed {
		t.Fatal("clear block revived revoked credential")
	}
	m = f.m(d, "rotate")
	d = f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.DeviceTx(ctx, tx, m, d.Devices[0].ID, "rotate") })
	if !d.Decision.Allowed || d.Devices[0].Credential.Version != 2 {
		t.Fatal("explicit new credential")
	}
	var audits, intents int
	if err = f.p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action LIKE 'access.%'").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err = f.p.QueryRow(ctx, "SELECT count(*) FROM access_outbox").Scan(&intents); err != nil || audits != intents || intents != int(d.User.Revision) {
		t.Fatal("non-atomic audit/outbox", audits, intents, err)
	}
}
func TestConcurrentIdempotencyConflictAndCAS(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	m := f.m(Detail{}, "create")
	var wg sync.WaitGroup
	results := make(chan Detail, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.CreateTx(ctx, tx, m, "Same customer") })
			results <- d
			errs <- err
		}()
	}
	wg.Wait()
	a, b := <-results, <-results
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if a.User.ID != b.User.ID || a.OutboxPending != 1 {
		t.Fatal("duplicate create")
	}
	_, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.CreateTx(ctx, tx, m, "Changed customer") })
	if !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	m1, m2 := f.m(a, "state"), f.m(a, "block")
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) {
				if i == 0 {
					return f.s.StateTx(ctx, tx, m1, "suspended")
				}
				return f.s.BlockTx(ctx, tx, m2, BlockChange{Scope: "user", Reason: "manual"})
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	e1, e2 := <-errs, <-errs
	if !((e1 == nil && errors.Is(e2, ErrRevision)) || (e2 == nil && errors.Is(e1, ErrRevision))) {
		t.Fatal("CAS collision", e1, e2)
	}
	d := f.read(a.User.ID)
	if d.User.Revision != 2 || d.OutboxPending != 2 {
		t.Fatal("lost update")
	}
}
func TestDeviceProofReplayExpiryCrossUserAndLastSlot(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a := f.entitlement(f.create("Customer A"), "set", time.Now().Add(time.Hour), 1)
	b := f.entitlement(f.create("Customer B"), "set", time.Now().Add(time.Hour), 2)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, err := f.challenge(a, pub)
	if err != nil {
		t.Fatal(err)
	}
	a = f.read(a.User.ID)
	if _, err = f.register(b, c, priv, "Wrong owner"); !errors.Is(err, ErrProof) {
		t.Fatal("cross-owner proof", err)
	}
	// Sign with a wholly different key, avoiding malformed keys.
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = f.register(a, c, wrong, "Bad proof"); !errors.Is(err, ErrProof) {
		t.Fatal("invalid proof", err)
	}
	m := f.m(a, "register")
	r := Register{c.ID, base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(c.SigningMessage))), "Phone A"}
	a = f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.RegisterTx(ctx, tx, m, r) })
	retry, replay, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.RegisterTx(ctx, tx, m, r) })
	if err != nil || !replay || retry.User.Revision != a.User.Revision {
		t.Fatal("lost registration response", err)
	}
	if _, err = f.register(a, c, priv, "Phone A"); !errors.Is(err, ErrChallengeUsed) {
		t.Fatal("challenge replay", err)
	}
	cb, err := f.challenge(b, pub)
	if err != nil {
		t.Fatal(err)
	}
	b = f.read(b.User.ID)
	if _, err = f.register(b, cb, priv, "Bound key"); !errors.Is(err, ErrBound) {
		t.Fatal("key rebound", err)
	}
	p2, k2, _ := ed25519.GenerateKey(rand.Reader)
	c2, err := f.challenge(a, p2)
	if err != nil {
		t.Fatal(err)
	}
	a = f.read(a.User.ID)
	if _, err = f.register(a, c2, k2, "Last slot"); !errors.Is(err, ErrLimit) {
		t.Fatal("over limit", err)
	}
	if _, err = f.p.Exec(ctx, "UPDATE access_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", c2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.register(a, c2, k2, "Expired"); !errors.Is(err, ErrChallengeExpired) {
		t.Fatal("expired proof", err)
	}
}
func TestConcurrentLastSlotAndRevokedKeyTombstone(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	d := f.entitlement(f.create("Last slot customer"), "set", time.Now().Add(time.Hour), 1)
	pub1, key1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
	c1, err := f.challenge(d, pub1)
	if err != nil {
		t.Fatal(err)
	}
	d = f.read(d.User.ID)
	c2, err := f.challenge(d, pub2)
	if err != nil {
		t.Fatal(err)
	}
	d = f.read(d.User.ID)
	m1, m2 := f.m(d, "register"), f.m(d, "register")
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, c := range []Challenge{c1, c2} {
		wg.Add(1)
		go func(i int, c Challenge) {
			defer wg.Done()
			key, m := key1, m1
			if i == 1 {
				key, m = key2, m2
			}
			r := Register{c.ID, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(c.SigningMessage))), "Concurrent phone"}
			_, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.RegisterTx(ctx, tx, m, r) })
			errs <- err
		}(i, c)
	}
	wg.Wait()
	e1, e2 := <-errs, <-errs
	if !((e1 == nil && errors.Is(e2, ErrRevision)) || (e2 == nil && errors.Is(e1, ErrRevision))) {
		t.Fatal(e1, e2)
	}
	d = f.read(d.User.ID)
	if len(d.Devices) != 1 {
		t.Fatal("slot overbooked")
	}
	registered := d.Devices[0]
	loser, loserKey := c1, key1
	if registered.PublicKey == base64.RawURLEncoding.EncodeToString(pub1) {
		loser, loserKey = c2, key2
	}
	if _, err = f.register(d, loser, loserKey, "Retry last slot"); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	m := f.m(d, "revoke")
	d = f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.DeviceTx(ctx, tx, m, registered.ID, "revoke") })
	if d.Decision.Allowed {
		t.Fatal("revoked decision")
	}
	key, pub := key1, pub1
	if registered.PublicKey != base64.RawURLEncoding.EncodeToString(pub1) {
		key, pub = key2, pub2
	}
	c, err := f.challenge(d, pub)
	if err != nil {
		t.Fatal(err)
	}
	d = f.read(d.User.ID)
	if _, err = f.register(d, c, key, "Resurrect"); !errors.Is(err, ErrBound) {
		t.Fatal("revoked key resurrected", err)
	}
	d, err = f.register(d, loser, loserKey, "Replacement phone")
	if err != nil || len(d.Devices) != 2 || !d.Decision.Allowed {
		t.Fatal("released slot", err)
	}
}
func TestCredentialsEncryptedVersionedAndMissingKeyAtomic(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	d := f.entitlement(f.create("Credential customer"), "set", time.Now().Add(time.Hour), 2)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, err := f.challenge(d, pub)
	if err != nil {
		t.Fatal(err)
	}
	d = f.read(d.User.ID)
	vault := f.s.Vault
	f.s.Vault = nil
	if _, err = f.register(d, c, priv, "No key"); !errors.Is(err, ErrKey) {
		t.Fatal(err)
	}
	unchanged := f.read(d.User.ID)
	if unchanged.User.Revision != d.User.Revision || len(unchanged.Devices) != 0 {
		t.Fatal("partial registration")
	}
	f.s.Vault = vault
	d, err = f.register(d, c, priv, "Encrypted phone")
	if err != nil {
		t.Fatal(err)
	}
	first := d.Devices[0]
	var encrypted []byte
	if err = f.p.QueryRow(ctx, "SELECT ciphertext FROM access_credentials WHERE id=$1", first.Credential.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	plain, err := vault.Open(encrypted, CredentialAAD(d.User.ID, first.ID, first.Credential.ID, 1))
	if err != nil || len(plain) != 32 || bytes.Contains(encrypted, plain) {
		t.Fatal("ciphertext boundary", err)
	}
	if _, err = vault.Open(encrypted, CredentialAAD(d.User.ID, first.ID, first.Credential.ID, 2)); err == nil {
		t.Fatal("AAD not version-bound")
	}
	raw, _ := json.Marshal(d)
	if bytes.Contains(raw, plain) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(plain))) || bytes.Contains(raw, []byte("ciphertext")) {
		t.Fatal("credential leaked")
	}
	m := f.m(d, "rotate")
	d = f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.DeviceTx(ctx, tx, m, first.ID, "rotate") })
	_, replay, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.DeviceTx(ctx, tx, m, first.ID, "rotate") })
	if err != nil || !replay {
		t.Fatal(err)
	}
	var count, active int
	if err = f.p.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE state='active') FROM access_credentials WHERE device_id=$1", first.ID).Scan(&count, &active); err != nil || count != 2 || active != 1 {
		t.Fatal("rotation duplicate", count, active, err)
	}
	d, _ = f.device(d, "Other phone")
	other := d.Devices[1].ID
	m = f.m(d, "block-device")
	d = f.must(func(tx pgx.Tx) (Detail, bool, error) {
		return f.s.BlockTx(ctx, tx, m, BlockChange{Scope: "device", DeviceID: &first.ID, Reason: "security"})
	})
	if d.Devices[0].Decision.Allowed || !d.Devices[1].Decision.Allowed || d.Devices[1].ID != other {
		t.Fatal("device isolation")
	}
	blockedRevision := d.User.Revision
	m = f.m(d, "blocked-rotate")
	_, _, err = f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.DeviceTx(ctx, tx, m, first.ID, "rotate") })
	if !errors.Is(err, ErrConflict) {
		t.Fatal("blocked device received credential", err)
	}
	current := f.read(d.User.ID)
	if current.User.Revision != blockedRevision || current.OutboxPending != d.OutboxPending || current.Devices[0].Credential.Version != 2 {
		t.Fatal("blocked rotation partial mutation")
	}
}
func TestQuotaUnknownGroupDisableAndExpiryReconciliation(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	d := f.entitlement(f.create("Expiry customer"), "set", time.Now().Add(time.Hour), 1)
	d, _ = f.device(d, "Expiry phone")
	quota := int64(1024)
	limit := 1
	group := DefaultGroupID
	expiry := time.Now().Add(time.Hour)
	m := f.m(d, "quota")
	d = f.must(func(tx pgx.Tx) (Detail, bool, error) {
		return f.s.EntitlementTx(ctx, tx, m, EntitlementChange{Action: "set", ExpiresAt: &expiry, DeviceLimit: &limit, GroupID: &group, QuotaBytes: &quota})
	})
	if d.Decision.Allowed || d.Decision.Reason != "quota_unknown" {
		t.Fatal("missing usage assumed zero")
	}
	d = f.entitlement(d, "set", expiry, 1)
	if _, err := f.p.Exec(ctx, "UPDATE access_groups SET enabled=false WHERE id=$1", group); err != nil {
		t.Fatal(err)
	}
	if f.read(d.User.ID).Decision.Reason != "group_disabled" {
		t.Fatal("disabled group granted")
	}
	if _, err := f.p.Exec(ctx, "UPDATE access_groups SET enabled=true WHERE id=$1", group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE access_entitlements SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1", d.User.ID); err != nil {
		t.Fatal(err)
	}
	if f.read(d.User.ID).Decision.Reason != "entitlement_expired" {
		t.Fatal("expiry waited for worker")
	}
	var wg sync.WaitGroup
	counts := make(chan int, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); n, err := f.s.ReconcileExpired(ctx, 10); counts <- n; errs <- err }()
	}
	wg.Wait()
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if (<-counts)+(<-counts) != 1 {
		t.Fatal("duplicate expiry")
	}
	after := f.read(d.User.ID)
	if after.User.Revision != d.User.Revision+1 || after.Entitlement.State != "expired" {
		t.Fatal("expiry not persisted")
	}
	if n, err := New(f.p, f.s.Vault).ReconcileExpired(ctx, 10); err != nil || n != 0 {
		t.Fatal("restart repeated expiry", n, err)
	}
	after = f.entitlement(after, "renew", time.Now().Add(2*time.Hour), 0)
	if !after.Decision.Allowed {
		t.Fatal("explicit renewal after expiry")
	}
}

func TestAccessMutationRollsBackOnOutboxFailure(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	d := f.create("Atomic customer")
	if _, err := f.p.Exec(ctx, "ALTER TABLE access_outbox ADD CONSTRAINT fixture_reject_next CHECK(revision<2)"); err != nil {
		t.Fatal(err)
	}
	m := f.m(d, "state")
	_, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.StateTx(ctx, tx, m, "suspended") })
	if err == nil {
		t.Fatal("fixture should reject commit")
	}
	current := f.read(d.User.ID)
	if current.User.State != "active" || current.User.Revision != 1 || current.OutboxPending != 1 {
		t.Fatal("partial access mutation")
	}
	var mutations, audits int
	if err = f.p.QueryRow(ctx, "SELECT count(*) FROM access_mutations").Scan(&mutations); err != nil {
		t.Fatal(err)
	}
	if err = f.p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action LIKE 'access.%'").Scan(&audits); err != nil || mutations != 1 || audits != 1 {
		t.Fatal("partial idempotency/audit", mutations, audits, err)
	}
	if _, err = f.p.Exec(ctx, "ALTER TABLE access_outbox DROP CONSTRAINT fixture_reject_next"); err != nil {
		t.Fatal(err)
	}
	current = f.must(func(tx pgx.Tx) (Detail, bool, error) { return f.s.StateTx(ctx, tx, m, "suspended") })
	if current.User.Revision != 2 || current.User.State != "suspended" {
		t.Fatal("retry after rollback")
	}
}
func TestConcurrentCrossUserInstallationKeyCannotRebind(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	a := f.entitlement(f.create("Binding user A"), "set", time.Now().Add(time.Hour), 1)
	b := f.entitlement(f.create("Binding user B"), "set", time.Now().Add(time.Hour), 1)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c1, err := f.challenge(a, pub)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := f.challenge(b, pub)
	if err != nil {
		t.Fatal(err)
	}
	a, b = f.read(a.User.ID), f.read(b.User.ID)
	m1, m2 := f.m(a, "register"), f.m(b, "register")
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, c := range []Challenge{c1, c2} {
		wg.Add(1)
		go func(i int, c Challenge) {
			defer wg.Done()
			m := m1
			if i == 1 {
				m = m2
			}
			r := Register{c.ID, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(c.SigningMessage))), "Shared installation"}
			_, _, err := f.tx(func(tx pgx.Tx) (Detail, bool, error) { return f.s.RegisterTx(ctx, tx, m, r) })
			errs <- err
		}(i, c)
	}
	wg.Wait()
	e1, e2 := <-errs, <-errs
	if !((e1 == nil && errors.Is(e2, ErrBound)) || (e2 == nil && errors.Is(e1, ErrBound))) {
		t.Fatal("global ownership race", e1, e2)
	}
	a, b = f.read(a.User.ID), f.read(b.User.ID)
	if len(a.Devices)+len(b.Devices) != 1 {
		t.Fatal("key bound twice")
	}
}

func TestForwardEntitlementIdentityMigrationPreservesTerminalRights(t *testing.T) {
	p := dbtest.NewUnmigrated(t)
	ctx := context.Background()
	if _, err := p.Exec(ctx, "CREATE TABLE schema_migrations(version integer PRIMARY KEY,name text UNIQUE NOT NULL,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"001_foundation.sql", "002_identity.sql", "003_access.sql"} {
		raw, err := fs.ReadFile(migrations.Files, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Exec(ctx, string(raw)); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		if _, err = p.Exec(ctx, "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)", i+1, name, fmt.Sprintf("%x", hash[:])); err != nil {
			t.Fatal(err)
		}
	}
	id, _ := database.NewID()
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	if _, err := p.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,'Upgrade fixture')", id); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, "INSERT INTO access_entitlements(user_id,state,expires_at,device_limit,group_id,quota_bytes,revision) VALUES($1,'refunded',$2,3,$3,4096,7)", id, expires, DefaultGroupID); err != nil {
		t.Fatal(err)
	}
	// Model an immutable 003 response before entitlement IDs existed. The old
	// request must replay this snapshot after the forward migration, not the
	// current entitlement or an invented empty UUID.
	oldUser, err := scanUser(p.QueryRow(ctx, "SELECT "+userColumns+" FROM access_users WHERE id=$1", id))
	if err != nil {
		t.Fatal(err)
	}
	quotaValue := int64(4096)
	old := Detail{User: oldUser, Entitlement: &Entitlement{State: "refunded", ExpiresAt: expires, DeviceLimit: 3, GroupID: DefaultGroupID, QuotaBytes: &quotaValue, Revision: 7}, Devices: []Device{}, Blocks: []Block{}, Decision: deny("entitlement_refunded"), OutboxPending: 0}
	oldJSON, err := json.Marshal(old)
	if err != nil || bytes.Contains(oldJSON, []byte(`"id":""`)) {
		t.Fatal("invalid historical snapshot")
	}
	actor, _ := database.NewID()
	m := Mutation{ActorID: actor, Route: "fixture/refund", TargetID: id, Revision: 1, Key: "historical-replay-0001"}
	change := EntitlementChange{Action: "refund"}
	requestJSON, _ := json.Marshal(struct {
		Revision int64 `json:"revision"`
		Payload  any   `json:"payload"`
	}{m.Revision, change})
	requestHash := sha256.Sum256(requestJSON)
	if _, err = p.Exec(ctx, "INSERT INTO access_mutations(actor_id,route,target_id,idempotency_key,request_hash,result) VALUES($1,$2,$3,$4,$5,$6)", actor, m.Route, id, m.Key, requestHash[:], oldJSON); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, p); err != nil {
		t.Fatal(err)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Rollback(tx)
	replayed, replay, err := New(p, nil).EntitlementTx(ctx, tx, m, change)
	if err != nil || !replay {
		t.Fatal("historical retry failed", err)
	}
	replayJSON, _ := json.Marshal(replayed)
	if !bytes.Equal(replayJSON, oldJSON) {
		t.Fatal("historical retry altered snapshot")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var entitlementID, state, group string
	var gotExpiry time.Time
	var limit int
	var quota, rev int64
	if err := p.QueryRow(ctx, "SELECT id::text,state,expires_at,device_limit,group_id::text,quota_bytes,revision FROM access_entitlements WHERE user_id=$1", id).Scan(&entitlementID, &state, &gotExpiry, &limit, &group, &quota, &rev); err != nil {
		t.Fatal(err)
	}
	tx, err = p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Rollback(tx)
	current, err := New(p, nil).DetailTx(ctx, tx, id)
	if err != nil || current.Entitlement.ID != entitlementID || current.Decision.Allowed {
		t.Fatal("fresh read must have identity and preserve denial", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if !database.ValidID(entitlementID) || entitlementID == id || state != "refunded" || !gotExpiry.Equal(expires) || limit != 3 || group != DefaultGroupID || quota != 4096 || rev != 7 {
		t.Fatal("identity migration changed right")
	}
	if err := database.Migrate(ctx, p); err != nil {
		t.Fatal(err)
	}
	var stable string
	if err := p.QueryRow(ctx, "SELECT id::text FROM access_entitlements WHERE user_id=$1", id).Scan(&stable); err != nil || stable != entitlementID {
		t.Fatal("migration retry replaced identity", err)
	}
}
