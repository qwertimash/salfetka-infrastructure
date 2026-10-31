package xrayengine

import (
	"encoding/json"
	"net/http"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/releases"
	"strings"
	"testing"
)

// Existing real agent integration calls this helper before the access revoke.
// The personal URL is downloaded without an admin cookie, then used by Xray.
func personalSubscriptionFlow(t *testing.T, client *http.Client, call func(string, string, any, int64, int, any), user access.Detail, node, tcp, udp string) (*flow, *flow, string) {
	t.Helper()
	var d releases.Detail
	network, _ := json.Marshal(map[string]any{"dns_servers": []string{"1.1.1.1"}, "probe": map[string]any{"url": "https://probe.example.invalid/check", "ipv4": "192.0.2.1", "expected_status": 200, "body_sha256": strings.Repeat("a", 64)}})
	recipe := releases.Recipe{NodeIDs: []string{node}, MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1, Network: compiler.PolicyChoice{Authority: "custom", Value: network}, Routing: map[string]compiler.PolicyChoice{"vpn": {Authority: "custom", Value: json.RawMessage(`{"id":"vpn-rules","title":"VPN rules","default_action":"tunnel","rules":[{"id":"direct-example","action":"direct","match":{"type":"domain_suffix","value":"example.com"}}]}`)}}, Locations: []compiler.Location{{ID: "custom-location", Title: "Constructor location", Country: "DE", Mode: "vpn", Kind: "location", Selection: "native", Members: []compiler.Member{{NodeID: node}}}}}}
	change := func(op, id string, r *releases.Recipe) {
		t.Helper()
		call("POST", "/api/v1/subscriptions/mutate", releases.Mutation{Operation: op, UserID: user.User.ID, DeviceID: user.Devices[0].ID, Revision: d.Subscription.Revision, TokenRevision: d.Subscription.TokenRevision, ReleaseID: id, Recipe: r}, 0, 200, &d)
	}
	change("stage", "", &recipe)
	change("publish", d.Releases[0].ID, nil)
	first := d.Releases[0].ID
	change("rotate", "", nil)
	var link struct {
		URL string `json:"url"`
	}
	call("POST", "/api/v1/subscriptions/link", map[string]string{"user_id": user.User.ID, "device_id": user.Devices[0].ID}, 0, 200, &link)
	download := func() map[string]any {
		t.Helper()
		response, e := client.Get(link.URL)
		if e != nil {
			t.Fatal("personal download failed")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("personal download status")
		}
		var m map[string]any
		if json.NewDecoder(response.Body).Decode(&m) != nil {
			t.Fatal("personal manifest JSON")
		}
		return m
	}
	manifest := download()
	check(t, manifest["version"] == float64(2) && manifest["locations"].([]any)[0].(map[string]any)["title"] == "Constructor location", "constructor layout not delivered")
	config := manifest["connections"].([]any)[0].(map[string]any)["settings"].(map[string]any)["xray_config"].(map[string]any)
	config["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": freePort(t, false), "protocol": "socks", "settings": map[string]any{"udp": true}}}
	engine := startEngine(t, config)
	ct, cu := openFlow(t, engine, "tcp", tcp), openFlow(t, engine, "udp", udp)
	check(t, ct.exchange([]byte("personal-before")) && cu.exchange([]byte("personal-udp-before")), "personal URL config failed traffic")
	change("stage", "", &recipe)
	check(t, download()["revision"] == manifest["revision"], "staging switched assignment")
	change("publish", d.Releases[0].ID, nil)
	check(t, download()["revision"] == float64(2) && ct.exchange([]byte("personal-after-publish")) && cu.exchange([]byte("personal-udp-after-publish")), "publish interrupted original flows")
	change("rollback", first, nil)
	change("publish", d.Releases[0].ID, nil)
	check(t, download()["revision"] == float64(3) && ct.exchange([]byte("personal-after-rollback")) && cu.exchange([]byte("personal-udp-after-rollback")), "rollback interrupted original flows")
	t.Log("personal URL: actual Xray TCP/UDP, stable link, same active streams across stage/publish/monotonic rollback")
	return ct, cu, link.URL
}
