package access

import (
	"context"
	"github.com/jackc/pgx/v5"
	"reflect"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
	"testing"
	"time"
)

func resolveVPN(t *testing.T, f *accessFixture, node string) []nodewire.VPNGrant {
	t.Helper()
	tx, e := f.p.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer database.Rollback(tx)
	grants, e := f.s.VPNGrantsTx(context.Background(), tx, node, DefaultGroupID, 1, time.Now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	return grants
}
func TestVPNMaterialUsesAccessDecisionsAndNodeIsolation(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	node := "11111111-1111-4111-8111-111111111111"
	other := "22222222-2222-4222-8222-222222222222"
	a := f.entitlement(f.create("Первый тест"), "set", time.Now().Add(time.Hour), 2)
	a, _ = f.device(a, "Первый телефон")
	b := f.entitlement(f.create("Второй тест"), "set", time.Now().Add(time.Hour), 2)
	b, _ = f.device(b, "Второй телефон")
	grants := resolveVPN(t, f, node)
	if len(grants) != 2 {
		t.Fatal("two eligible users missing")
	}
	foreign := resolveVPN(t, f, other)
	if len(foreign) != 2 {
		t.Fatal("other node")
	}
	for i := range grants {
		if grants[i].ID != foreign[i].ID || grants[i].Credential == foreign[i].Credential || !database.ValidID(grants[i].Credential) {
			t.Fatal("wire credential binding")
		}
	}
	repeat := resolveVPN(t, f, node)
	for i := range grants {
		if repeat[i].Credential != grants[i].Credential {
			t.Fatal("credential unstable")
		}
	}
	m := f.m(a, "block")
	a = f.must(func(tx pgx.Tx) (Detail, bool, error) {
		return f.s.BlockTx(ctx, tx, m, BlockChange{Scope: "user", Reason: "policy"})
	})
	a = f.entitlement(a, "renew", time.Now().Add(2*time.Hour), 0)
	after := resolveVPN(t, f, node)
	if len(after) != 1 || after[0].ID != b.Devices[0].Credential.ID {
		t.Fatal("renew restored blocked user or denied B")
	}
	b = f.entitlement(b, "refund", time.Time{}, 0)
	if len(resolveVPN(t, f, node)) != 0 {
		t.Fatal("refund retained wire grant")
	}
	// Existing access projection stays honest until the delivery/ACK stage exists.
	if f.read(a.User.ID).Decision.NodeState != "not_provisioned" {
		t.Fatal("resolver falsely reported applied")
	}
}
func TestVPNMaterialDoesNotChangeOutboxOrStoredCredential(t *testing.T) {
	f := fixture(t)
	d := f.entitlement(f.create("Без выдачи"), "set", time.Now().Add(time.Hour), 1)
	d, _ = f.device(d, "Телефон теста")
	before := f.read(d.User.ID)
	resolveVPN(t, f, "11111111-1111-4111-8111-111111111111")
	after := f.read(d.User.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("read resolver mutated projection")
	}
}

func TestBackendKeysAreIndependentAndStable(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	node, credential := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	v := backendCredential(secret, node, credential, "")
	h := backendCredential(secret, node, credential, "hysteria2")
	o := backendCredential(secret, node, credential, "olcrtc")
	if v == h || h == o || len(o) != 64 || v != wireCredential(secret, node, credential) || h != backendCredential(secret, node, credential, "hysteria2") {
		t.Fatal("credential domains")
	}
	if o == backendCredential(secret, credential, node, "olcrtc") {
		t.Fatal("node scope")
	}
}
