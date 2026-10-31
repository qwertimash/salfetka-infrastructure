package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
	"salfetka/panel/internal/subscriptionsets"
)

func TestSubscriptionSetsHTTPVersionsAssignmentsAndReplay(t *testing.T) {
	f := newFixture(t)
	a := f.handler.(*api)
	a.config.Vault, _ = secrets.New(bytes.Repeat([]byte{18}, 32))
	owner := f.owner(t)
	user, _ := database.NewID()
	if _, e := f.pool.Exec(context.Background(), "INSERT INTO access_users(id,name) VALUES($1,'Set HTTP fixture')", user); e != nil {
		t.Fatal(e)
	}
	post := func(path, key string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		raw, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		w := call(f.handler, "POST", "/api/v1/subscription-sets"+path, string(raw), &owner, accessHeaders(0, key))
		status(t, w, want)
		return w
	}
	doc := builder.Document{Title: "Основная подписка", Recipe: releases.Recipe{MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1}}}
	create := subscriptionsets.Save{Document: doc}
	var first, second subscriptionsets.Set
	if e := json.Unmarshal(post("/save", "sets-http-create-0001", create, 200).Body.Bytes(), &first); e != nil {
		t.Fatal(e)
	}
	create.Document.Title = "Только обходы"
	if e := json.Unmarshal(post("/save", "sets-http-create-0002", create, 200).Body.Bytes(), &second); e != nil {
		t.Fatal(e)
	}
	for i, set := range []subscriptionsets.Set{first, second} {
		post("/assign", fmt.Sprintf("sets-http-assign-%04d", i), subscriptionsets.Assign{UserID: user, SetID: set.ID, State: "active"}, 200)
	}
	get := func(path string, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := call(f.handler, "GET", "/api/v1/subscription-sets"+path, "", &owner, nil)
		status(t, w, want)
		return w
	}
	var page subscriptionsets.AssignmentPage
	if e := json.Unmarshal(get("/assignments?user_id="+user, 200).Body.Bytes(), &page); e != nil || len(page.Items) != 2 {
		t.Fatal("assignments", e)
	}
	post("/save", "sets-http-update-0001", subscriptionsets.Save{ID: first.ID, Revision: 1, Document: create.Document}, 200)
	var old, current subscriptionsets.Set
	json.Unmarshal(get("/"+first.ID+"?revision=1", 200).Body.Bytes(), &old)
	json.Unmarshal(get("/"+first.ID, 200).Body.Bytes(), &current)
	if old.Document.Title != doc.Title || current.Revision != 2 || current.Document.Title != create.Document.Title {
		t.Fatal("version query")
	}
	post("/save", "sets-http-stale-0001", subscriptionsets.Save{ID: first.ID, Revision: 1, Document: doc}, 409)
	post("/assign", "sets-http-revoke-0001", subscriptionsets.Assign{UserID: user, SetID: first.ID, State: "revoked", Revision: 1}, 200)
	w := post("/assign", "sets-http-assign-0000", subscriptionsets.Assign{UserID: user, SetID: first.ID, State: "active"}, 200)
	if w.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("missing replay header")
	}
	json.Unmarshal(get("/assignments?user_id="+user, 200).Body.Bytes(), &page)
	for _, assignment := range page.Items {
		if assignment.SetID == first.ID && assignment.State != "revoked" {
			t.Fatal("stale request granted access")
		}
	}
	for _, path := range []string{"?unused=x", "?after=x", "?after=&after=", "/assignments", "/assignments?user_id=" + user + "&user_id=" + user, "/" + first.ID + "?revision=0", "/" + first.ID + "?revision=no", "/" + first.ID + "?revision=1&revision=2", "?after=%zz"} {
		get(path, 400)
	}
	get("/"+first.ID+"?revision=999", 404)
	for _, body := range []string{`{"document":{},"document":{}}`, `{"actor":"injected","document":{}}`, `{"unexpected":true}`} {
		status(t, call(f.handler, "POST", "/api/v1/subscription-sets/save", body, &owner, accessHeaders(0, "sets-invalid-json-0001")), 400)
	}
	var n int
	if e := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM subscriptions").Scan(&n); e != nil || n != 0 {
		t.Fatal("draft API published delivery", e)
	}
	if bytes.Contains(get("", 200).Body.Bytes(), []byte("recipe")) {
		t.Fatal("list exposes recipe instead of summaries")
	}
}

func TestSubscriptionSetsHTTPPermissionsAndPublicListener(t *testing.T) {
	f := newFixture(t)
	a := f.handler.(*api)
	a.config.Vault, _ = secrets.New(bytes.Repeat([]byte{18}, 32))
	owner := f.owner(t)
	const base = "/api/v1/subscription-sets"
	status(t, call(f.handler, "GET", base, "", nil, nil), 401)
	status(t, call(f.handler, "DELETE", base, "", &owner, nil), 405)
	status(t, call(f.handler, "POST", base+"/save", "{}", &owner, map[string]string{"Origin": "https://different.invalid"}), 403)
	h := accessHeaders(0, "sets-csrf-check-0001")
	h["X-CSRF-Token"] = "invalid"
	status(t, call(f.handler, "POST", base+"/save", "{}", &owner, h), 403)
	status(t, call(f.handler, "POST", base+"/save", "{}", &owner, nil), 400)
	for _, role := range []identity.Role{identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor} {
		u, e := f.store.CreateAdmin(context.Background(), owner.Token, "sets_"+string(role), testPassword, role)
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.store.Login(context.Background(), u.Username, testPassword, "sets-local")
		if e != nil {
			t.Fatal(e)
		}
		read, save, assign := 403, 403, 403
		if role == identity.InfrastructureOperator {
			read, save = 200, 400
		}
		if role == identity.AccessOperator {
			read, assign = 200, 400
		}
		status(t, call(f.handler, "GET", base, "", &session, nil), read)
		status(t, call(f.handler, "POST", base+"/save", "{}", &session, accessHeaders(0, "sets-rbac-save-0001")), save)
		status(t, call(f.handler, "POST", base+"/assign", "{}", &session, accessHeaders(0, "sets-rbac-assign-001")), assign)
	}
	a.config.DeliveryOnly = true
	status(t, call(f.handler, "GET", base, "", &owner, nil), 404)
	status(t, call(f.handler, "POST", base+"/assign", "{}", &owner, accessHeaders(0, "sets-public-check-01")), 404)
}

func TestSubscriptionSetPublishAndAssignmentLinkHTTP(t *testing.T) {
	f := newFixture(t)
	a := f.handler.(*api)
	a.config.Vault, _ = secrets.New(bytes.Repeat([]byte{18}, 32))
	a.releases = releases.New(f.pool, a.config.Vault, a.nodes)
	owner := f.owner(t)
	const base = "/api/v1/subscription-sets"
	doc := builder.Document{Title: "HTTP publication", Recipe: releases.Recipe{MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1}}}
	post := func(path, key string, input any, want int) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(input)
		w := call(f.handler, "POST", base+path, string(b), &owner, accessHeaders(0, key))
		status(t, w, want)
		return w
	}
	var set subscriptionsets.Set
	json.Unmarshal(post("/save", "http-publish-create-1", subscriptionsets.Save{Document: doc}, 200).Body.Bytes(), &set)
	user, _ := database.NewID()
	if _, e := f.pool.Exec(context.Background(), "INSERT INTO access_users(id,name) VALUES($1,'HTTP waiting device')", user); e != nil {
		t.Fatal(e)
	}
	var assign subscriptionsets.Assignment
	json.Unmarshal(post("/assign", "http-publish-assign-1", subscriptionsets.Assign{UserID: user, SetID: set.ID, State: "active"}, 200).Body.Bytes(), &assign)
	input := subscriptionsets.Publish{ID: set.ID, Revision: 1}
	var publication subscriptionsets.Publication
	json.Unmarshal(post("/publish", "http-publish-request", input, 200).Body.Bytes(), &publication)
	if publication.WaitingUsers != 1 || publication.Published != 0 {
		t.Fatal("no device falsely published", publication)
	}
	if post("/publish", "http-publish-request", input, 200).Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("publish retry")
	}
	status(t, call(f.handler, "GET", base+"/publications/"+publication.ID, "", &owner, nil), 200)
	status(t, call(f.handler, "GET", base+"/targets?publication_id="+publication.ID, "", &owner, nil), 200)
	var link struct {
		URL string `json:"url"`
	}
	json.Unmarshal(post("/link", "unused-link-request", map[string]string{"assignment_id": assign.ID}, 200).Body.Bytes(), &link)
	if !strings.HasPrefix(link.URL, a.config.SubscriptionOrigin+"/a/") {
		t.Fatal("wrong link format")
	}
	path := strings.TrimPrefix(link.URL, a.config.SubscriptionOrigin)
	// Public listener accepts only the proof resolver, never administrator paths.
	a.config.DeliveryOnly = true
	status(t, call(f.handler, "GET", path, "", nil, nil), 200)
	status(t, call(f.handler, "POST", path, `{"device_id":"00000000-0000-4000-8000-000000000001","issued_at":1,"signature":"invalid"}`, nil, nil), 404)
	status(t, call(f.handler, "POST", base+"/publish", "{}", &owner, accessHeaders(0, "public-admin-denied")), 404)
	a.config.DeliveryOnly = false
	token := strings.TrimPrefix(path, "/a/")
	if strings.Contains(f.logs.String(), token) {
		t.Fatal("assignment token in request logs")
	}
	for _, role := range []identity.Role{identity.InfrastructureOperator, identity.AccessOperator} {
		admin, e := f.store.CreateAdmin(context.Background(), owner.Token, "publication_"+string(role), testPassword, role)
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.store.Login(context.Background(), admin.Username, testPassword, "publication-local")
		if e != nil {
			t.Fatal(e)
		}
		want := 403
		if role == identity.AccessOperator {
			want = 400
		}
		status(t, call(f.handler, "POST", base+"/publish", "{}", &session, accessHeaders(0, "http-publish-rbac-01")), want)
		status(t, call(f.handler, "POST", base+"/link", "{}", &session, nil), want)
	}
}
