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
	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionHTTPFullLifecycle(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate_delivery_%v", separate), func(t *testing.T) { subscriptionHTTPFullLifecycle(t, separate) })
	}
}
func subscriptionHTTPFullLifecycle(t *testing.T, separate bool) {
	f := newFixture(t)
	v, _ := secrets.New(bytes.Repeat([]byte{23}, 32))
	a := f.handler.(*api)
	a.access = access.New(f.pool, v)
	a.catalog = catalog.New(f.pool, v)
	a.releases = releases.New(f.pool, v, a.nodes)
	owner := f.owner(t)
	delivery := f.handler
	if separate {
		a.config.SubscriptionOrigin = "https://subscriptions.example.test"
		var err error
		delivery, err = New(f.pool, Config{Origin: a.config.SubscriptionOrigin, DeliveryOnly: true, Vault: v})
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/", "/index.html", "/api/v1/setup", "/api/v1/setup/status", "/api/v1/auth/session", "/api/v1/access/users", "/api/v1/subscriptions/link", "/api/v1/node/heartbeat", "/api/v1/builder", "/s/../api/v1/auth/session", "/%61pi/v1/auth/session"} {
			for _, method := range []string{"GET", "HEAD", "POST"} {
				status(t, call(delivery, method, path, "{}", &owner, map[string]string{"X-Forwarded-Host": "localhost:18443"}), 404)
			}
		}
	}
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
	input := releases.Mutation{Operation: "stage", UserID: d.User.ID, DeviceID: d.Devices[0].ID, Recipe: &releases.Recipe{SourceID: src.ID, VersionID: src.Current.ID, ExternalCredentials: true, NodeIDs: []string{}, MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}}}
	raw, _ := json.Marshal(input)
	status(t, call(f.handler, "POST", "/api/v1/subscriptions/mutate", string(raw), nil, nil), 401)
	status(t, call(f.handler, "POST", "/api/v1/subscriptions/mutate", string(raw), &owner, map[string]string{"Origin": "https://evil.invalid"}), 403)
	status(t, call(f.handler, "POST", "/api/v1/subscriptions/mutate", string(raw), &owner, map[string]string{"X-CSRF-Token": "bad"}), 403)
	for _, role := range []identity.Role{identity.Support, identity.Auditor, identity.InfrastructureOperator} {
		u, e := f.store.CreateAdmin(context.Background(), owner.Token, "subscriptions_"+string(role), testPassword, role)
		if e != nil {
			t.Fatal(e)
		}
		s, e := f.store.Login(context.Background(), u.Username, testPassword, "subscription-local")
		if e != nil {
			t.Fatal(e)
		}
		status(t, call(f.handler, "POST", "/api/v1/subscriptions/mutate", string(raw), &s, nil), 403)
		status(t, call(f.handler, "POST", "/api/v1/subscriptions/link", `{}`, &s, nil), 403)
	}
	var out releases.Detail
	json.Unmarshal(post("/subscriptions/mutate", input, 0, 200), &out)
	input.Recipe = nil
	input.Operation = "publish"
	input.Revision = out.Subscription.Revision
	input.ReleaseID = out.Releases[0].ID
	json.Unmarshal(post("/subscriptions/mutate", input, 0, 200), &out)
	input.Operation = "rotate"
	input.ReleaseID = ""
	input.Revision = out.Subscription.Revision
	json.Unmarshal(post("/subscriptions/mutate", input, 0, 200), &out)
	var link struct {
		URL string `json:"url"`
	}
	json.Unmarshal(post("/subscriptions/link", map[string]string{"user_id": d.User.ID, "device_id": d.Devices[0].ID}, 0, 200), &link)
	path := strings.TrimPrefix(link.URL, a.config.SubscriptionOrigin)
	if !strings.HasPrefix(path, "/s/") {
		t.Fatal("link")
	}
	get := call(delivery, "GET", path, "", nil, nil)
	status(t, get, 200)
	head := call(delivery, "HEAD", path, "", nil, nil)
	status(t, head, 200)
	if head.Body.Len() != 0 || get.Header().Get("Content-Length") != head.Header().Get("Content-Length") || get.Header().Get("Cache-Control") != "no-store" || get.Header().Get("Vary") != "Accept" {
		t.Fatal("HEAD/cache")
	}
	if _, e = importer.Parse(get.Body.Bytes(), time.Now()); e != nil {
		t.Fatal(e)
	}
	status(t, call(delivery, "GET", path, "", nil, map[string]string{"Accept": "text/html;version=1"}), 406)
	status(t, call(delivery, "GET", path, "", nil, map[string]string{"Accept": "application/json;q=0, application/vnd.salfetka.subscription+json;q=0, */*;q=1"}), 406)
	status(t, call(delivery, "GET", path, "", nil, map[string]string{"Accept": "application/vnd.salfetka.subscription+json;version=2"}), 406)
	status(t, call(delivery, "GET", path+"?x=1", "", nil, nil), 404)
	before := get.Body.String()
	json.Unmarshal(post("/subscriptions/mutate", releases.Mutation{Operation: "stage", UserID: d.User.ID, DeviceID: d.Devices[0].ID, Revision: out.Subscription.Revision, Recipe: &releases.Recipe{SourceID: src.ID, VersionID: src.Current.ID, ExternalCredentials: true, MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}}}, 0, 200), &out)
	if call(delivery, "GET", path, "", nil, nil).Body.String() != before {
		t.Fatal("staging changed link")
	}
	post(route+"/blocks", map[string]string{"scope": "user", "reason": "manual"}, d.User.Revision, 200)
	for _, method := range []string{"GET", "HEAD"} {
		denied := call(delivery, method, path, "", nil, nil)
		status(t, denied, 404)
		if denied.Body.Len() != 0 {
			t.Fatal("denied body")
		}
	}
	if strings.Contains(f.logs.String(), strings.TrimPrefix(path, "/s/")) || strings.Contains(f.logs.String(), "settings") {
		t.Fatal("secret logs")
	}
}

func TestSubscriptionMediaNegotiation(t *testing.T) {
	for _, tc := range []struct {
		accept  string
		version int
		media   string
		ok      bool
	}{
		{"application/json", 1, "application/json", true},
		{"application/json, text/plain, application/octet-stream", 2, "application/json", true},
		{"application/json;q=0, */*;q=1", 1, "application/vnd.salfetka.subscription+json", true},
		{"application/vnd.salfetka.subscription+json;version=1", 2, "", false},
		{"text/html;version=1", 1, "", false},
		{"*/*;q=0", 1, "", false},
		{"application/json;q=0.3, application/vnd.salfetka.subscription+json;q=0.9", 1, "application/vnd.salfetka.subscription+json", true},
	} {
		media, ok := manifestMedia(tc.accept, tc.version)
		if ok != tc.ok || media != tc.media {
			t.Fatal("negotiation mismatch", tc.accept)
		}
	}
}
