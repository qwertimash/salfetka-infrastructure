package nodes

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

func seedVPNUser(t *testing.T, f *fixture) (string, string) {
	t.Helper()
	ctx := context.Background()
	user, _ := database.NewID()
	device, _ := database.NewID()
	credential, _ := database.NewID()
	entitlement, _ := database.NewID()
	key := make([]byte, 32)
	rand.Read(key)
	cipher, e := f.s.Vault.Seal(key, access.CredentialAAD(user, device, credential, 1))
	if e != nil {
		t.Fatal(e)
	}
	public := make([]byte, 32)
	rand.Read(public)
	e = f.tx(func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,'VPN fixture')", user); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "INSERT INTO access_entitlements(id,user_id,state,expires_at,device_limit,group_id,revision) VALUES($1,$2,'active',clock_timestamp()+interval '1 hour',1,$3,1)", entitlement, user, access.DefaultGroupID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "INSERT INTO access_devices(id,user_id,name,state,public_key) VALUES($1,$2,'VPN fixture','registered',$3)", device, user, public); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, "INSERT INTO access_credentials(id,user_id,device_id,version,state,ciphertext) VALUES($1,$2,$3,1,'active',$4)", credential, user, device, cipher)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return user, credential
}
func TestVPNIssuanceConcurrentReplayEncryptedAndRetiredEpoch(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	installation, _ := database.NewID()
	m := f.m(n, "vpn_configure")
	var configured VPNInstallation
	if e := f.tx(func(tx pgx.Tx) error {
		var e error
		configured, _, e = f.s.ConfigureVPNTx(ctx, tx, m, installation, access.DefaultGroupID, true)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.tx(func(tx pgx.Tx) error {
		_, replay, e := f.s.ConfigureVPNTx(ctx, tx, m, installation, access.DefaultGroupID, true)
		if e == nil && !replay {
			t.Error("config replay")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	a, aid := seedVPNUser(t, f)
	_, bid := seedVPNUser(t, f)
	request := VPNFetch{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, EngineEpoch: strings.Repeat("a", 32)}
	results := make(chan nodewire.SignedVPNPolicy, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, _, e := f.s.VPNDesired(ctx, cert, request)
			if e != nil {
				t.Error(e)
				return
			}
			results <- *out.Policy
		}()
	}
	wg.Wait()
	close(results)
	var first nodewire.SignedVPNPolicy
	count := 0
	for signed := range results {
		if count == 0 {
			first = signed
		} else if signed != first {
			t.Fatal("concurrent issuance changed bytes/deadline")
		}
		count++
	}
	if count != 8 {
		t.Fatal("missing issuance")
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	policy, e := nodecontrol.VerifyVPN(pub, first)
	if e != nil || len(policy.Grants) != 2 || policy.Generation != 1 {
		t.Fatal("signed active users", e)
	}
	var ciphertext []byte
	var rows int
	if e = f.p.QueryRow(ctx, "SELECT policy_ciphertext FROM nodes_vpn_policies WHERE node_id=$1 AND generation=1", n.ID).Scan(&ciphertext); e != nil {
		t.Fatal(e)
	}
	for _, g := range policy.Grants {
		if bytes.Contains(ciphertext, []byte(g.Credential)) {
			t.Fatal("wire credential stored plaintext")
		}
	}
	if e = f.p.QueryRow(ctx, "SELECT count(*) FROM nodes_vpn_policies WHERE node_id=$1", n.ID).Scan(&rows); e != nil || rows != 1 {
		t.Fatal("duplicate policy")
	}
	if _, e = f.p.Exec(ctx, "UPDATE nodes_vpn_policies SET policy_sha256=policy_sha256 WHERE node_id=$1", n.ID); e == nil {
		t.Fatal("immutable policy changed")
	}
	// A business denial changes desired set immediately, without waiting for lease renewal.
	if _, e = f.p.Exec(ctx, "UPDATE access_users SET state='suspended',revision=revision+1 WHERE id=$1", a); e != nil {
		t.Fatal(e)
	}
	out, replay, e := f.s.VPNDesired(ctx, cert, request)
	if e != nil || replay {
		t.Fatal("business denial not issued", e)
	}
	denied, e := nodecontrol.VerifyVPN(pub, *out.Policy)
	if e != nil || denied.Generation != 2 || len(denied.Grants) != 1 || denied.Grants[0].ID != bid || denied.Grants[0].ID == aid {
		t.Fatal("A denial disrupted B")
	}
	request.EngineEpoch = strings.Repeat("b", 32)
	out, _, e = f.s.VPNDesired(ctx, cert, request)
	if e != nil {
		t.Fatal(e)
	}
	fresh, _ := nodecontrol.VerifyVPN(pub, *out.Policy)
	if fresh.Generation != 3 {
		t.Fatal("new process did not advance generation")
	}
	old := request
	old.EngineEpoch = strings.Repeat("a", 32)
	if _, _, e = f.s.VPNDesired(ctx, cert, old); !errors.Is(e, ErrConflict) {
		t.Fatal("retired process epoch revived", e)
	}
	wrong := request
	wrong.InstallationID = "99999999-9999-4999-8999-999999999999"
	if _, _, e = f.s.VPNDesired(ctx, cert, wrong); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("foreign installation", e)
	}
	// Explicit disable creates a complete deny-all policy, not a disappearing response.
	m = f.m(Node{ID: n.ID, Revision: configured.NodeRevision}, "vpn_disable")
	if e = f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.ConfigureVPNTx(ctx, tx, m, installation, access.DefaultGroupID, false)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	out, _, e = f.s.VPNDesired(ctx, cert, request)
	if e != nil {
		t.Fatal(e)
	}
	empty, _ := nodecontrol.VerifyVPN(pub, *out.Policy)
	if empty.Generation != 4 || len(empty.Grants) != 0 {
		t.Fatal("disable not denied")
	}
	if _, e = f.p.Exec(ctx, "UPDATE nodes_registry SET state='revoked' WHERE id=$1", n.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.s.VPNDesired(ctx, cert, request); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("revoked node read secrets", e)
	}
}
func TestVPNProjectionLeaseRenewalAndSignerFailureAtomicity(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	installation, _ := database.NewID()
	m := f.m(n, "vpn_configure")
	if e := f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.ConfigureVPNTx(ctx, tx, m, installation, access.DefaultGroupID, true)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	seedVPNUser(t, f)
	request := VPNFetch{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, EngineEpoch: strings.Repeat("c", 32)}
	out, _, e := f.s.VPNDesired(ctx, cert, request)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	p, _ := nodecontrol.VerifyVPN(pub, *out.Policy)
	a := projectionHash(p.Grants, p.ExpiresAt, access.DefaultGroupID, true)
	shift := make([]nodewire.VPNGrant, len(p.Grants))
	copy(shift, p.Grants)
	for i := range shift {
		shift[i].ExpiresAt = shift[i].ExpiresAt.Add(time.Second)
		shift[i].Generation++
	}
	if a != projectionHash(shift, p.ExpiresAt.Add(time.Second), access.DefaultGroupID, true) {
		t.Fatal("rolling lease changed authorization projection")
	}
	// Fault injection changes only mutable scheduling metadata; stored signed deadline stays immutable.
	if _, e = f.p.Exec(ctx, "UPDATE nodes_vpn_installations SET policy_expires_at=clock_timestamp()+interval '20 seconds' WHERE node_id=$1", n.ID); e != nil {
		t.Fatal(e)
	}
	renewed, replay, e := f.s.VPNDesired(ctx, cert, request)
	if e != nil || replay {
		t.Fatal("renewal window", e)
	}
	next, _ := nodecontrol.VerifyVPN(pub, *renewed.Policy)
	if next.Generation != 2 || !next.ExpiresAt.After(p.ExpiresAt) {
		t.Fatal("renewal generation")
	}
	oldSigner := f.s.Signer
	f.s.Signer = nil
	if _, _, e = f.s.VPNDesired(ctx, cert, request); !errors.Is(e, ErrKey) {
		t.Fatal("missing signing key")
	}
	f.s.Signer = oldSigner
	var rows int
	f.p.QueryRow(ctx, "SELECT count(*) FROM nodes_vpn_policies WHERE node_id=$1", n.ID).Scan(&rows)
	if rows != 2 {
		t.Fatal("failed issuance mutated history")
	}
	body, _ := json.Marshal(renewed)
	if len(body) == 0 {
		t.Fatal("empty response")
	}
}
