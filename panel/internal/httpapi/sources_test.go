package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/secrets"
)

func TestSourceHTTPPreviewCommitRBACAndSecretIsolation(t *testing.T) {
	f := newFixture(t)
	vault, _ := secrets.New(bytes.Repeat([]byte{6}, 32))
	f.handler.(*api).catalog = catalog.New(f.pool, vault)
	owner := f.owner(t)
	status(t, call(f.handler, "GET", "/sources", "", nil, nil), 200)
	uri := "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?security=tls#private-label"
	body, _ := json.Marshal(catalog.Input{Name: "Synthetic source", Kind: "upload", Input: uri})
	status(t, call(f.handler, "POST", "/api/v1/sources/preview", string(body), nil, nil), 401)
	status(t, call(f.handler, "POST", "/api/v1/sources/preview", string(body), &owner, map[string]string{"Origin": "https://evil.invalid"}), 403)
	status(t, call(f.handler, "POST", "/api/v1/sources/preview", string(body), &owner, map[string]string{"X-CSRF-Token": "bad"}), 403)
	for _, bad := range []string{`{"name":"A","name":"B","kind":"upload","input":"x"}`, `{"name":"aa","kind":"upload","input":"\ud800"}`, `{"name":"aa","kind":"upload","input":"x","extra":1}`} {
		status(t, call(f.handler, "POST", "/api/v1/sources/preview", bad, &owner, nil), 400)
	}
	w := call(f.handler, "POST", "/api/v1/sources/preview", string(body), &owner, nil)
	status(t, w, 201)
	var d catalog.Draft
	json.Unmarshal(w.Body.Bytes(), &d)
	for _, secret := range []string{"11111111", "private-label", "vpn.example.com", "settings"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("preview leaked input")
		}
	}
	m := catalog.Mutation{Operation: "create", DraftID: d.ID}
	b, _ := json.Marshal(m)
	headers := map[string]string{"Idempotency-Key": "source-http-00001"}
	w = call(f.handler, "POST", "/api/v1/sources/mutate", string(b), &owner, headers)
	status(t, w, 200)
	var n catalog.Source
	json.Unmarshal(w.Body.Bytes(), &n)
	retry := call(f.handler, "POST", "/api/v1/sources/mutate", string(b), &owner, headers)
	status(t, retry, 200)
	if retry.Header().Get("Idempotent-Replayed") != "true" || w.Body.String() != retry.Body.String() {
		t.Fatal("lost ACK replay")
	}
	for _, r := range []identity.Role{identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor} {
		user, e := f.store.CreateAdmin(context.Background(), owner.Token, "source_"+string(r), testPassword, r)
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.store.Login(context.Background(), user.Username, testPassword, "source-test")
		if e != nil {
			t.Fatal(e)
		}
		w = call(f.handler, "GET", "/api/v1/sources", "", &session, nil)
		status(t, w, 200)
		if strings.Contains(w.Body.String(), "private-label") {
			t.Fatal("list secret")
		}
		want := 403
		if r == identity.InfrastructureOperator {
			want = 201
		}
		status(t, call(f.handler, "POST", "/api/v1/sources/preview", string(body), &session, nil), want)
	}
	if strings.Contains(f.logs.String(), "11111111") || strings.Contains(f.logs.String(), uri) {
		t.Fatal("input leaked to logs")
	}
	// A known-good source persists when another import is rejected.
	bad, _ := json.Marshal(catalog.Input{Name: "Broken source", Kind: "upload", Input: uri + "\nss://unsupported"})
	status(t, call(f.handler, "POST", "/api/v1/sources/preview", string(bad), &owner, nil), 422)
	w = call(f.handler, "GET", "/api/v1/sources", "", &owner, nil)
	status(t, w, 200)
	if !strings.Contains(w.Body.String(), n.ID) {
		t.Fatal("failed import cleared source")
	}
	status(t, call(f.handler, "POST", "/api/v1/sources/mutate", fmt.Sprintf(`{"operation":"pause","id":%q,"revision":0,"draft_id":"","version_id":"","paused":true}`, n.ID), &owner, map[string]string{"Idempotency-Key": "source-http-00002"}), 400)
}
