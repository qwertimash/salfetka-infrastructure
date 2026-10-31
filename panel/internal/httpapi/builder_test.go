package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
	"strings"
	"testing"
	"time"
)

func TestBuilderHTTPStagePreviewPublishAndRoles(t *testing.T) {
	f := newFixture(t)
	v, _ := secrets.New(bytes.Repeat([]byte{23}, 32))
	a := f.handler.(*api)
	a.config.Vault = v
	a.access = access.New(f.pool, v)
	a.catalog = catalog.New(f.pool, v)
	a.releases = releases.New(f.pool, v, a.nodes)
	owner := f.owner(t)
	seq := 0
	post := func(path string, body any, revision int64, want int) []byte {
		t.Helper()
		seq++
		b, _ := json.Marshal(body)
		w := call(f.handler, "POST", "/api/v1"+path, string(b), &owner, accessHeaders(revision, fmt.Sprintf("subscription-http-%05d", seq)))
		status(t, w, want)
		return w.Body.Bytes()
	}
	var d access.Detail
	json.Unmarshal(post("/access/users", map[string]any{"name": "Subscription customer"}, 0, 201), &d)
	route := "/access/users/" + d.User.ID
	json.Unmarshal(post(route+"/entitlement", map[string]any{"action": "set", "expires_at": time.Now().Add(48 * time.Hour), "device_limit": 2, "group_id": access.DefaultGroupID}, d.User.Revision, 200), &d)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var c access.Challenge
	json.Unmarshal(post(route+"/devices/challenges", map[string]string{"public_key": base64.RawURLEncoding.EncodeToString(pub)}, d.User.Revision, 201), &c)
	json.Unmarshal(post(route+"/devices/register", map[string]string{"challenge_id": c.ID, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(c.SigningMessage))), "name": "HTTP phone"}, c.UserRevision, 200), &d)
	b, e := os.ReadFile("../../tests/compatibility/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &fixture)
	var draft catalog.Draft
	json.Unmarshal(post("/sources/preview", catalog.Input{Name: "HTTP source", Kind: "upload", Input: string(fixture.Cases[0].Expected)}, 0, 201), &draft)
	var src catalog.Source
	json.Unmarshal(post("/sources/mutate", catalog.Mutation{Operation: "create", DraftID: draft.ID}, 0, 200), &src)
	var outline compiler.SourceOutline
	json.Unmarshal(post("/builder/source", map[string]string{"id": src.ID, "version_id": src.Current.ID}, 0, 200), &outline)
	var locations []struct {
		ID, Title, Country, Mode, Kind string
		Members                        []string `json:"connection_ids"`
		Selection                      struct{ Type string }
	}
	json.Unmarshal(outline.Locations, &locations)
	bp := &compiler.Blueprint{Version: 1, Network: compiler.PolicyChoice{Authority: "source", SourceID: src.ID}, Routing: map[string]compiler.PolicyChoice{"vpn": {Authority: "source", SourceID: src.ID}, "bypass": {Authority: "source", SourceID: src.ID}}}
	for _, l := range locations {
		loc := compiler.Location{ID: l.ID, Title: l.Title, Country: l.Country, Mode: l.Mode, Kind: l.Kind, Selection: l.Selection.Type}
		for _, id := range l.Members {
			loc.Members = append(loc.Members, compiler.Member{SourceID: src.ID, ConnectionID: id})
		}
		bp.Locations = append(bp.Locations, loc)
	}
	document := builder.Document{Title: "Constructor HTTP", Recipe: releases.Recipe{Sources: []releases.SourceRef{{ID: src.ID, VersionID: src.Current.ID}}, ExternalCredentials: true, NodeIDs: []string{}, MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}, Blueprint: bp}}
	var draftOut builder.Draft
	save := builder.Mutation{Document: document}
	json.Unmarshal(post("/builder/save", save, 0, 200), &draftOut)
	if draftOut.Revision != 1 {
		t.Fatal("draft not saved")
	}
	get := call(f.handler, "GET", "/api/v1/builder/"+draftOut.ID, "", &owner, nil)
	status(t, get, 200)
	if !strings.Contains(get.Body.String(), "Constructor HTTP") {
		t.Fatal("draft missing")
	}
	status(t, call(f.handler, "POST", "/api/v1/builder/save", `{"document":{},"document":{}}`, &owner, accessHeaders(0, "builder-duplicate-json")), 400)
	status(t, call(f.handler, "POST", "/api/v1/builder/save", `{"document":{},"unexpected":true}`, &owner, accessHeaders(0, "builder-unknown-json")), 400)
	stage := map[string]any{"id": draftOut.ID, "revision": draftOut.Revision, "mutation": releases.Mutation{Operation: "stage", UserID: d.User.ID, DeviceID: d.Devices[0].ID}}
	raw, _ := json.Marshal(stage)
	for _, role := range []identity.Role{identity.Support, identity.Auditor, identity.InfrastructureOperator, identity.AccessOperator} {
		u, e := f.store.CreateAdmin(context.Background(), owner.Token, "builder_"+string(role), testPassword, role)
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.store.Login(context.Background(), u.Username, testPassword, "builder-local")
		if e != nil {
			t.Fatal(e)
		}
		if role != identity.AccessOperator {
			status(t, call(f.handler, "POST", "/api/v1/builder/stage", string(raw), &session, accessHeaders(0, "builder-role-check-001")), 403)
		}
		if role != identity.InfrastructureOperator {
			b, _ := json.Marshal(save)
			status(t, call(f.handler, "POST", "/api/v1/builder/save", string(b), &session, accessHeaders(0, "builder-role-save-001")), 403)
		}
		if role == identity.Support || role == identity.Auditor {
			status(t, call(f.handler, "GET", "/api/v1/builder/"+draftOut.ID, "", &session, nil), 403)
		}
	}
	staged := call(f.handler, "POST", "/api/v1/builder/stage", string(raw), &owner, accessHeaders(0, "builder-exact-stage-001"))
	status(t, staged, 200)
	var detail releases.Detail
	json.Unmarshal(staged.Body.Bytes(), &detail)
	if len(detail.Releases) != 1 {
		t.Fatal("stage")
	}
	var pv releases.Preview
	json.Unmarshal(post("/builder/preview", map[string]string{"user_id": d.User.ID, "device_id": d.Devices[0].ID, "release_id": detail.Releases[0].ID}, 0, 200), &pv)
	if len(pv.Candidate.Profiles) != 5 || pv.AccessChanged || pv.ServerRestart || pv.Current != nil {
		t.Fatal("preview scope")
	}
	save.ID = draftOut.ID
	save.Revision = 1
	save.Document.Title = "Edited after staging"
	post("/builder/save", save, 0, 200)
	replay := call(f.handler, "POST", "/api/v1/builder/stage", string(raw), &owner, accessHeaders(0, "builder-exact-stage-001"))
	status(t, replay, 200)
	if replay.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("lost ACK not recovered")
	}
	post("/builder/stage", stage, 0, 409)
	mutate := releases.Mutation{Operation: "publish", UserID: d.User.ID, DeviceID: d.Devices[0].ID, Revision: detail.Subscription.Revision, ReleaseID: detail.Releases[0].ID}
	json.Unmarshal(post("/subscriptions/mutate", mutate, 0, 200), &detail)
	mutate.Operation = "rotate"
	mutate.ReleaseID = ""
	mutate.Revision = detail.Subscription.Revision
	json.Unmarshal(post("/subscriptions/mutate", mutate, 0, 200), &detail)
	var link struct{ URL string }
	json.Unmarshal(post("/subscriptions/link", map[string]string{"user_id": d.User.ID, "device_id": d.Devices[0].ID}, 0, 200), &link)
	delivered := call(f.handler, "GET", strings.TrimPrefix(link.URL, a.config.Origin), "", nil, nil)
	status(t, delivered, 200)
	view, e := compiler.Present(delivered.Body.Bytes(), time.Now())
	if e != nil || view.PolicyDigest != pv.Candidate.PolicyDigest {
		t.Fatal("preview differs from personal delivery", e)
	}
	var decoded map[string]any
	json.Unmarshal(staged.Body.Bytes(), &decoded)
	if bytes.Contains(staged.Body.Bytes(), []byte("key_hex")) || bytes.Contains(get.Body.Bytes(), []byte("xray_config")) {
		t.Fatal("secret escaped projection")
	}
}
