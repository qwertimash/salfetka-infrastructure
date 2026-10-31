package compiler

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"reflect"
	"salfetka/panel/internal/importer"
	"testing"
	"time"
)

func TestFrozenGoldenSemanticParity(t *testing.T) {
	b, e := os.ReadFile("../../tests/compatibility/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Cases []struct {
			Name     string
			Expected json.RawMessage
		}
	}
	if json.Unmarshal(b, &f) != nil {
		t.Fatal("fixture")
	}
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for _, tc := range f.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			r, e := importer.Parse(tc.Expected, now)
			if e != nil {
				t.Fatal(e)
			}
			in := Input{ID: "personal-test", Revision: 1, Title: "Personal test", Now: now, ExpiresAt: now.Add(24 * time.Hour), LeaseUntil: now.Add(time.Hour), MaxVersion: 2, Engines: []string{"xray", "openflux", "olcrtc"}, Source: &Source{Format: "manifest", Normalized: r.Normalized, ValidUntil: r.Preview.ValidUntil, ExpiresAt: r.Preview.SubscriptionExpiresAt}}
			before := bytes.Clone(in.Source.Normalized)
			got, e := Build(in)
			if e != nil {
				t.Fatal(e)
			}
			again, e := Build(in)
			if e != nil || !bytes.Equal(got.Body, again.Body) || got.Digest != again.Digest || !bytes.Equal(before, in.Source.Normalized) {
				t.Fatal("determinism")
			}
			expected, _ := importer.Decode(tc.Expected)
			actual, _ := importer.Decode(got.Body)
			for _, field := range []string{"connections", "locations", "network", "routing", "version"} {
				if !reflect.DeepEqual(expected.(map[string]any)[field], actual.(map[string]any)[field]) {
					t.Fatal("semantic drift", field)
				}
			}
			in.Engines = []string{}
			if _, e = Build(in); e != ErrCapability {
				t.Fatal("capability must not drop profiles")
			}
			in.Engines = []string{"xray", "openflux", "olcrtc"}
			in.LeaseUntil = now
			if _, e = Build(in); e == nil {
				t.Fatal("expired lease")
			}
		})
	}
}

func TestLimitsAndMissingMappingRejectWholeArtifact(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	uri := "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?security=tls"
	r, e := importer.Parse([]byte(uri), now)
	if e != nil {
		t.Fatal(e)
	}
	in := Input{ID: "limits", Revision: 1, Title: "Limits", Now: now, ExpiresAt: now.Add(time.Hour), LeaseUntil: now.Add(time.Hour), MaxVersion: 2, Engines: []string{"xray"}, Source: &Source{Format: "uri", Normalized: r.Normalized}}
	if _, e = Build(in); e != ErrMapping {
		t.Fatal("invented network metadata")
	}
	b, _ := os.ReadFile("../../tests/compatibility/fixtures.json")
	var f struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &f)
	v, _ := importer.Decode(f.Cases[0].Expected)
	m := v.(map[string]any)
	in.Network = raw(m["network"])
	in.Locations = raw([]any{Object{"id": "location", "mode": "vpn", "kind": "location", "title": "Explicit", "connection_ids": []any{"record-1"}, "selection": Object{"type": "first_working"}}})
	if _, e = Build(in); e != nil {
		t.Fatal(e)
	}
	config := raw(Object{"outbounds": []any{Object{"tag": "vpn", "protocol": "vless", "settings": Object{"vnext": []any{Object{"address": "vpn.example.com", "port": 443, "users": []any{Object{"id": "11111111-1111-4111-8111-111111111111", "encryption": "none"}}}}}, "streamSettings": Object{"network": "tcp", "security": "tls", "tlsSettings": Object{"serverName": "vpn.example.com"}}}}})
	for i := 0; i < 32; i++ {
		in.Nodes = append(in.Nodes, Node{ID: recordID(i), Title: "Node", Config: config})
	}
	if a, e := Build(in); e == nil || len(a.Body) != 0 {
		t.Fatal("oversize result truncated")
	}
}

func TestMultipleSourcesPreservePoliciesAndRejectConflicts(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	b, _ := os.ReadFile("../../tests/compatibility/fixtures.json")
	var f struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &f)
	r, e := importer.Parse(f.Cases[0].Expected, now)
	if e != nil {
		t.Fatal(e)
	}
	first := Source{ID: "first", VersionID: "one", Format: "manifest", Normalized: r.Normalized}
	second := first
	second.ID = "second"
	in := Input{ID: "merged", Revision: 1, Title: "Merged", Now: now, ExpiresAt: now.Add(time.Hour), LeaseUntil: now.Add(time.Hour), MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}, Sources: []Source{first, second}}
	result, e := Build(in)
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Preview.Profiles) != 10 {
		t.Fatal("source dropped")
	}
	again, e := Build(in)
	if e != nil || !bytes.Equal(result.Body, again.Body) {
		t.Fatal("merge not deterministic")
	}
	v, _ := importer.Decode(second.Normalized)
	m := v.(map[string]any)
	m["network"].(map[string]any)["dns_servers"] = []any{"8.8.8.8"}
	in.Sources[1].Normalized = raw(m)
	if a, e := Build(in); e != ErrPolicyConflict || len(a.Body) != 0 {
		t.Fatal("network conflict silently resolved")
	}
	in.Sources = []Source{first, first}
	if _, e = Build(in); e != ErrInvalid {
		t.Fatal("duplicate source")
	}
}

func TestUpstreamExpiryLimitsLeaseNotCustomerPaidExpiry(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	upstream := now.Add(6 * time.Hour)
	paid := now.Add(48 * time.Hour)
	b, _ := os.ReadFile("../../tests/compatibility/fixtures.json")
	var f struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &f)
	in := Input{ID: "separate-expiry", Revision: 1, Title: "Paid subscription", Now: now, ExpiresAt: paid, LeaseUntil: now.Add(24 * time.Hour), MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}, Source: &Source{Format: "manifest", Normalized: f.Cases[0].Expected, ExpiresAt: &upstream}}
	a, e := Build(in)
	if e != nil {
		t.Fatal(e)
	}
	if a.Preview.SubscriptionExpiresAt == nil || !a.Preview.SubscriptionExpiresAt.Equal(paid) || a.Preview.ValidUntil == nil || !a.Preview.ValidUntil.Equal(upstream) {
		t.Fatal("upstream availability replaced personal paid expiry")
	}
	in.Now = upstream.Add(time.Second)
	if _, e = Build(in); e == nil {
		t.Fatal("expired upstream silently renewed")
	}
}

func TestManagedBypassLocationsArePreserved(t *testing.T) {
	now := time.Now().UTC()
	b, _ := os.ReadFile("../../tests/compatibility/fixtures.json")
	var f struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &f)
	v, _ := importer.Decode(f.Cases[0].Expected)
	olc := raw(Object{"provider": "jitsi", "transport": "vp8channel", "room": "https://room.example.invalid/test", "key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bootstrap_dns": "1.1.1.1:53"})
	in := Input{ID: "managed", Revision: 1, Title: "Managed", Now: now, ExpiresAt: now.Add(time.Hour), LeaseUntil: now.Add(time.Hour), MaxVersion: 2, Engines: []string{"olcrtc"}, Network: raw(v.(map[string]any)["network"]), Nodes: []Node{{ID: "bypass", Title: "Bypass", Engine: "olcrtc", Config: olc}}}
	a, e := Build(in)
	if e != nil {
		t.Fatal(e)
	}
	m, _ := importer.Decode(a.Body)
	loc := m.(map[string]any)["locations"].([]any)[0].(map[string]any)
	if loc["mode"] != "bypass" || loc["selection"].(map[string]any)["type"] != "first_working" {
		t.Fatal("managed bypass published as VPN")
	}
	in.Engines = []string{"xray"}
	if _, e = Build(in); e != ErrCapability {
		t.Fatal("unsupported client dropped bypass")
	}
}

func TestManagedAccountSessionSurvivesPersonalPublication(t *testing.T) {
	now := time.Now().UTC()
	b, _ := os.ReadFile("../../tests/compatibility/fixtures.json")
	var f struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &f)
	v, _ := importer.Decode(f.Cases[0].Expected)
	for _, version := range []int{1, 2} {
		settings := Object{"provider": "jitsi", "transport": "vp8channel", "room": "https://room.example.invalid/account", "key_hex": strings.Repeat("a", 64), "bootstrap_dns": "1.1.1.1:53", "account_session": true}
		in := Input{ID: "account", Revision: 1, Title: "Account", Now: now, ExpiresAt: now.Add(time.Hour), LeaseUntil: now.Add(time.Hour), MaxVersion: version, Engines: []string{"olcrtc"}, Network: raw(v.(map[string]any)["network"]), Nodes: []Node{{ID: "account-node", Title: "Account", Engine: "olcrtc", Config: raw(settings)}}}
		result, e := Build(in)
		if e != nil {
			t.Fatal(version, e)
		}
		m, _ := importer.Decode(result.Body)
		connections := m.(map[string]any)["connections"].([]any)
		got := connections[0].(map[string]any)["settings"].(map[string]any)
		if got["account_session"] != true {
			t.Fatal("account capability silently lost")
		}
		for _, bad := range []any{"true", float64(1), nil} {
			settings["account_session"] = bad
			in.Nodes[0].Config = raw(settings)
			if _, e = Build(in); e == nil {
				t.Fatal("non boolean account mode published")
			}
		}
		settings["account_session"] = true
		settings["transport"] = "datachannel"
		in.Nodes[0].Config = raw(settings)
		if _, e = Build(in); e == nil {
			t.Fatal("unsupported account carrier published")
		}
		settings["transport"] = "vp8channel"
		settings["provider"] = "telemost"
		in.Nodes[0].Config = raw(settings)
		if _, e = Build(in); e == nil {
			t.Fatal("unsupported account provider published")
		}
	}
}
