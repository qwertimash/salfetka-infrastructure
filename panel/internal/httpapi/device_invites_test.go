package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
	"salfetka/panel/internal/subscriptionsets"
	"strings"
	"testing"
	"time"
)

func TestDeviceInvitationHTTPProofAndPublicBoundary(t *testing.T) {
	f := newFixture(t)
	a := f.handler.(*api)
	a.config.Vault, _ = secrets.New(bytes.Repeat([]byte{29}, 32))
	owner := f.owner(t)
	user, _ := database.NewID()
	entitlement, _ := database.NewID()
	if _, e := f.pool.Exec(context.Background(), "INSERT INTO access_users(id,name) VALUES($1,'Invite HTTP account')", user); e != nil {
		t.Fatal(e)
	}
	if _, e := f.pool.Exec(context.Background(), "INSERT INTO access_entitlements(id,user_id,state,expires_at,device_limit,group_id,revision) VALUES($1,$2,'active',clock_timestamp()+interval '1 day',2,$3,1)", entitlement, user, access.DefaultGroupID); e != nil {
		t.Fatal(e)
	}
	post := func(path, key string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := call(f.handler, "POST", "/api/v1/subscription-sets"+path, string(raw), &owner, accessHeaders(0, key))
		status(t, w, want)
		return w
	}
	var set subscriptionsets.Set
	doc := builder.Document{Title: "Invitation set", Recipe: releases.Recipe{MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1}}}
	json.Unmarshal(post("/save", "invites-http-save-0001", subscriptionsets.Save{Document: doc}, 200).Body.Bytes(), &set)
	var assignment subscriptionsets.Assignment
	json.Unmarshal(post("/assign", "invites-http-assign-0001", subscriptionsets.Assign{UserID: user, SetID: set.ID, State: "active"}, 200).Body.Bytes(), &assignment)
	var invite struct {
		URL       string    `json:"url"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	json.Unmarshal(post("/invite", "invites-http-mint-0001", map[string]string{"assignment_id": assignment.ID}, 200).Body.Bytes(), &invite)
	if invite.URL == "" || !invite.ExpiresAt.After(time.Now()) {
		t.Fatal("invalid invite receipt")
	}
	if post("/invite", "invites-http-mint-0001", map[string]string{"assignment_id": assignment.ID}, 200).Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("not replayed")
	}
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	route := "/i/" + token
	config := a.config
	config.DeliveryOnly = true
	public, e := New(f.pool, config)
	if e != nil {
		t.Fatal(e)
	}
	status(t, call(public, "GET", "/api/v1/subscription-sets", "", &owner, nil), 404)
	descriptor := call(public, "GET", route, "", nil, nil)
	status(t, descriptor, 200)
	if !strings.Contains(descriptor.Body.String(), user) || strings.Contains(descriptor.Body.String(), "Invite HTTP account") {
		t.Fatal("descriptor wrong")
	}
	status(t, call(public, "POST", route, `{}`, nil, nil), 404)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	proof := access.InviteProof{PublicKey: base64.RawURLEncoding.EncodeToString(pub), Name: "iPhone", IssuedAt: time.Now().Unix()}
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(access.InviteMessage(token, proof))))
	raw, _ := json.Marshal(proof)
	w := call(public, "POST", route, string(raw), nil, nil)
	status(t, w, 200)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	if response["user_id"] != user || !database.ValidID(response["device_id"]) || !strings.Contains(response["url"], "/a/") {
		t.Fatal("invalid onboarding response")
	}
	replay := call(public, "POST", route, string(raw), nil, nil)
	status(t, replay, 200)
	if replay.Body.String() != w.Body.String() {
		t.Fatal("lost response changes identity")
	}
	status(t, call(public, "POST", route+"?x=1", string(raw), nil, nil), 404)
	post("/assign", "invites-http-revoke-0001", subscriptionsets.Assign{UserID: user, SetID: set.ID, State: "revoked", Revision: assignment.Revision}, 200)
	status(t, call(public, "POST", route, string(raw), nil, nil), 404)
}
