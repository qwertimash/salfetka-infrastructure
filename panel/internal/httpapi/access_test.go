package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/secrets"
)

func accessHeaders(revision int64, key string) map[string]string {
	return map[string]string{"Idempotency-Key": key, "If-Match": strconv.Quote(strconv.FormatInt(revision, 10))}
}
func TestAccessHTTPRolesStrictRequestsAndIdempotency(t *testing.T) {
	f := newFixture(t)
	owner := f.owner(t)
	ctx := context.Background()
	route := "/api/v1/access/users"
	key := "http-create-first-0001"
	status(t, call(f.handler, "GET", route, "", nil, nil), 401)
	status(t, call(f.handler, "POST", route, `{"name":"HTTP customer"}`, &owner, nil), 400)
	status(t, call(f.handler, "POST", route, `{"name":"HTTP customer"}`, &owner, map[string]string{"Idempotency-Key": key, "Origin": "https://evil.example"}), 403)
	status(t, call(f.handler, "POST", route, `{"name":"HTTP customer"}`, &owner, map[string]string{"Idempotency-Key": key, "X-CSRF-Token": ""}), 403)
	for _, body := range []string{`{"name":"HTTP customer","name":"Other"}`, `{"name":"HTTP customer","unknown":true}`, `{"name":null}`, `{"name":"HTTP customer"} {}`, `{}`, `{"name":"x"}`} {
		status(t, call(f.handler, "POST", route, body, &owner, map[string]string{"Idempotency-Key": key}), 400)
	}
	w := call(f.handler, "POST", route, `{"name":"HTTP customer"}`, &owner, map[string]string{"Idempotency-Key": key})
	status(t, w, 201)
	var d access.Detail
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	retry := call(f.handler, "POST", route, `{"name":"HTTP customer"}`, &owner, map[string]string{"Idempotency-Key": key})
	status(t, retry, 201)
	if retry.Header().Get("Idempotent-Replayed") != "true" || retry.Body.String() != w.Body.String() {
		t.Fatal("create replay")
	}
	status(t, call(f.handler, "POST", route, `{"name":"Changed customer"}`, &owner, map[string]string{"Idempotency-Key": key}), 409)
	detail := route + "/" + d.User.ID
	status(t, call(f.handler, "GET", detail, "", &owner, nil), 200)
	status(t, call(f.handler, "GET", detail+"?surprise=true", "", &owner, nil), 400)
	expiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	body := fmt.Sprintf(`{"action":"set","expires_at":%q,"device_limit":2,"group_id":%q}`, expiry, access.DefaultGroupID)
	status(t, call(f.handler, "POST", detail+"/entitlement", body, &owner, map[string]string{"Idempotency-Key": "missing-ifmatch-0001"}), 400)
	w = call(f.handler, "POST", detail+"/entitlement", body, &owner, accessHeaders(1, "set-entitlement-0001"))
	status(t, w, 200)
	if w.Header().Get("ETag") != `"2"` {
		t.Fatal("revision ETag")
	}
	status(t, call(f.handler, "POST", detail+"/state", `{"state":"suspended"}`, &owner, accessHeaders(1, "stale-revision-0001")), 412)
	sessions := []identity.Session{owner}
	for _, role := range []identity.Role{identity.AccessOperator, identity.InfrastructureOperator, identity.Support, identity.Auditor} {
		u, err := f.store.CreateAdmin(ctx, owner.Token, "access_"+string(role), testPassword, role)
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.Login(ctx, u.Username, testPassword, "local")
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	for _, session := range sessions {
		t.Run(string(session.User.Role), func(t *testing.T) {
			readStatus, writeStatus := 200, 403
			if session.User.Role == identity.InfrastructureOperator {
				readStatus = 403
			}
			if session.User.Role == identity.Owner || session.User.Role == identity.AccessOperator {
				writeStatus = 201
			}
			for _, path := range []string{route, detail, "/api/v1/access/groups"} {
				status(t, call(f.handler, "GET", path, "", &session, nil), readStatus)
			}
			status(t, call(f.handler, "POST", route, `{"name":"Role customer"}`, &session, map[string]string{"Idempotency-Key": "role-creation-00001"}), writeStatus)
		})
	}
	// Transaction-bound authorization must reject the previously authenticated session.
	operator := sessions[1]
	role := identity.Support
	_, err := f.store.UpdateAdmin(ctx, owner.Token, operator.User.ID, operator.User.Revision, &role, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = f.store.WithAuthorizedSession(ctx, operator.Token, []identity.Role{identity.Owner, identity.AccessOperator}, func(tx pgx.Tx, current identity.Session) error {
		_, _, e := access.New(f.pool, nil).CreateTx(ctx, tx, access.Mutation{ActorID: current.User.ID, Route: route, Key: "stale-principal-0001"}, "Forbidden customer")
		return e
	})
	if err != identity.ErrUnauthorized {
		t.Fatal("stale principal mutated access", err)
	}
	for _, secret := range []string{owner.Token, owner.CSRFToken, "HTTP customer", body, "SELECT", "INSERT"} {
		if strings.Contains(f.logs.String(), secret) {
			t.Fatal("unsafe access log")
		}
	}
}
func TestAccessHTTPDeviceProofMetadataAndTerminalPolicy(t *testing.T) {
	f := newFixture(t)
	key := make([]byte, 32)
	rand.Read(key)
	vault, _ := secrets.New(key)
	f.handler.(*api).access = access.New(f.pool, vault)
	owner := f.owner(t)
	seq := 0
	mutate := func(path string, body any, revision int64, want int) []byte {
		t.Helper()
		seq++
		raw, _ := json.Marshal(body)
		w := call(f.handler, "POST", path, string(raw), &owner, accessHeaders(revision, fmt.Sprintf("device-http-key-%04d", seq)))
		status(t, w, want)
		return w.Body.Bytes()
	}
	var d access.Detail
	route := "/api/v1/access/users"
	if err := json.Unmarshal(mutate(route, map[string]any{"name": "Device customer"}, 0, 201), &d); err != nil {
		t.Fatal(err)
	}
	route += "/" + d.User.ID
	expiry := time.Now().UTC().Add(time.Hour)
	raw := mutate(route+"/entitlement", map[string]any{"action": "set", "expires_at": expiry, "device_limit": 2, "group_id": access.DefaultGroupID}, d.User.Revision, 200)
	json.Unmarshal(raw, &d)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw = mutate(route+"/devices/challenges", map[string]any{"public_key": base64.RawURLEncoding.EncodeToString(pub)}, d.User.Revision, 201)
	var c access.Challenge
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(c.SigningMessage)))
	raw = mutate(route+"/devices/register", map[string]any{"challenge_id": c.ID, "signature": signature, "name": "Synthetic phone"}, c.UserRevision, 200)
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if !d.Decision.Allowed || len(d.Devices) != 1 || d.Decision.NodeState != "not_provisioned" {
		t.Fatal("device decision")
	}
	for _, s := range []string{"ciphertext", "secret", "signature", signature} {
		if strings.Contains(string(raw), s) {
			t.Fatal("private response metadata")
		}
	}
	device := d.Devices[0].ID
	raw = mutate(route+"/devices/"+device+"/rotate", struct{}{}, d.User.Revision, 200)
	json.Unmarshal(raw, &d)
	if d.Devices[0].Credential.Version != 2 {
		t.Fatal("rotation")
	}
	raw = mutate(route+"/blocks", map[string]any{"scope": "user", "reason": "policy"}, d.User.Revision, 200)
	json.Unmarshal(raw, &d)
	block := d.Blocks[0].ID
	raw = mutate(route+"/entitlement", map[string]any{"action": "renew", "expires_at": expiry.Add(time.Hour)}, d.User.Revision, 200)
	json.Unmarshal(raw, &d)
	if d.Decision.Reason != "user_blocked" {
		t.Fatal("renew unblocked")
	}
	raw = mutate(route+"/blocks/"+block+"/clear", struct{}{}, d.User.Revision, 200)
	json.Unmarshal(raw, &d)
	if !d.Decision.Allowed {
		t.Fatal("clear")
	}
	raw = mutate(route+"/devices/"+device+"/revoke", struct{}{}, d.User.Revision, 200)
	json.Unmarshal(raw, &d)
	if d.Decision.Allowed || d.Devices[0].State != "revoked" || d.Devices[0].Credential.State != "revoked" {
		t.Fatal("revoke")
	}
	for _, secret := range []string{signature, c.SigningMessage, c.PublicKey, "Synthetic phone"} {
		if strings.Contains(f.logs.String(), secret) {
			t.Fatal("proof in logs")
		}
	}
}
