package httpapi

import (
	"context"
	"encoding/json"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"testing"
)

func TestServerGroupingHTTPRolesAndRetry(t *testing.T) {
	f, _ := nodeFixture(t)
	owner := f.owner(t)
	w := call(f.handler, "POST", "/api/v1/servers", `{"name":"Isolated machine","address":"203.0.113.10","domain":"pol.example.com"}`, &owner, accessHeaders(0, "server-http-create-0001"))
	status(t, w, 200)
	var server nodes.Server
	if e := json.Unmarshal(w.Body.Bytes(), &server); e != nil || server.ID == "" {
		t.Fatal("bad server", e)
	}
	replay := call(f.handler, "POST", "/api/v1/servers", `{"name":"Isolated machine","address":"203.0.113.10","domain":"pol.example.com"}`, &owner, accessHeaders(0, "server-http-create-0001"))
	status(t, replay, 200)
	if replay.Body.String() != w.Body.String() {
		t.Fatal("retry changed server")
	}
	for _, body := range []string{`{"name":"Missing domain","address":"203.0.113.10"}`, `{"name":"Invalid domain","address":"203.0.113.10","domain":"https://pol.example.com"}`} {
		status(t, call(f.handler, "POST", "/api/v1/servers", body, &owner, accessHeaders(0, "server-invalid-domain-0001")), 400)
	}
	for _, tc := range []struct{ name, address, domain, code string }{
		{"x", "203.0.113.10", "pol.example.com", "server_name_invalid"},
		{"Fixture", "228.22.232.21", "pol.example.com", "server_address_multicast"},
		{"Fixture", "::ffff:228.22.232.21", "pol.example.com", "server_address_multicast"},
		{"Fixture", "0.0.0.0", "pol.example.com", "server_address_unspecified"},
		{"Fixture", "https://203.0.113.10", "pol.example.com", "server_address_invalid"},
		{"Fixture", "203.0.113.10", "https://pol.example.com", "server_domain_invalid"},
	} {
		body, _ := json.Marshal(map[string]string{"name": tc.name, "address": tc.address, "domain": tc.domain})
		response := call(f.handler, "POST", "/api/v1/servers", string(body), &owner, accessHeaders(0, "server-field-error-0001"))
		status(t, response, 400)
		var result struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Error.Code != tc.code {
			t.Fatalf("wrong field error: %s", response.Body.String())
		}
	}
	route := "/api/v1/servers/" + server.ID + "/connections"
	w = call(f.handler, "POST", route, `{"name":"Private VLESS"}`, &owner, accessHeaders(0, "server-http-node-0001"))
	status(t, w, 200)
	var n nodes.Node
	json.Unmarshal(w.Body.Bytes(), &n)
	if n.ID == "" {
		t.Fatal("no connection")
	}
	var page nodes.ServerNodePage
	w = call(f.handler, "GET", route, "", &owner, nil)
	status(t, w, 200)
	json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 1 || page.Items[0].ID != n.ID {
		t.Fatal("wrong group")
	}
	history := "/api/v1/servers/" + n.ID + "/config-history"
	for _, r := range []identity.Role{identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor} {
		if _, e := f.store.CreateAdmin(context.Background(), owner.Token, string(r), testPassword, r); e != nil {
			t.Fatal(e)
		}
		s, e := f.store.Login(context.Background(), string(r), testPassword, string(r))
		if e != nil {
			t.Fatal(e)
		}
		status(t, call(f.handler, "GET", route, "", &s, nil), 200)
		want := 403
		if r == identity.InfrastructureOperator {
			want = 200
		}
		status(t, call(f.handler, "GET", history, "", &s, nil), want)
		status(t, call(f.handler, "POST", "/api/v1/servers", `{"name":"Another server","address":"203.0.113.11","domain":"other.example.com"}`, &s, accessHeaders(0, "server-role-create-0001")), want)
	}
	status(t, call(f.handler, "POST", "/api/v1/servers", `{"name":"No CSRF"}`, &owner, map[string]string{"X-CSRF-Token": ""}), 403)
	status(t, call(f.handler, "GET", route+"?after=x&after=y", "", &owner, nil), 400)
	f.handler.(*api).config.DeliveryOnly = true
	status(t, call(f.handler, "GET", route, "", &owner, nil), 404)
}
