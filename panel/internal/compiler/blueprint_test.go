package compiler

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func blueprintFixture(t *testing.T) Input {
	t.Helper()
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	b, e := os.ReadFile("../../tests/compatibility/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &f)
	source := Source{ID: "fixture", VersionID: "one", Format: "manifest", Normalized: f.Cases[0].Expected}
	outline, e := Outline(source, now)
	if e != nil {
		t.Fatal(e)
	}
	var locations []struct {
		ID, Title, Country, Mode, Kind string
		ConnectionIDs                  []string `json:"connection_ids"`
		Selection                      struct{ Type string }
	}
	json.Unmarshal(outline.Locations, &locations)
	bp := &Blueprint{Version: 1, Network: PolicyChoice{Authority: "source", SourceID: source.ID}, Routing: map[string]PolicyChoice{"vpn": {Authority: "source", SourceID: source.ID}, "bypass": {Authority: "source", SourceID: source.ID}}}
	for _, l := range locations {
		loc := Location{ID: l.ID, Title: l.Title, Country: l.Country, Mode: l.Mode, Kind: l.Kind, Selection: l.Selection.Type}
		for _, id := range l.ConnectionIDs {
			loc.Members = append(loc.Members, Member{SourceID: source.ID, ConnectionID: id})
		}
		bp.Locations = append(bp.Locations, loc)
	}
	return Input{ID: "blueprint", Title: "Preview", Revision: 1, Now: now, ExpiresAt: now.Add(time.Hour), LeaseUntil: now.Add(time.Hour), MaxVersion: 2, Engines: []string{"xray", "olcrtc", "openflux"}, Sources: []Source{source}, Blueprint: bp}
}
func TestBlueprintPreservesNativeAndPresentation(t *testing.T) {
	in := blueprintFixture(t)
	in.Blueprint.Locations[0].Title = "Выбранное название"
	in.Blueprint.Locations[0].Country = "DE"
	a, e := Build(in)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Build(in)
	if e != nil || !bytes.Equal(a.Body, b.Body) {
		t.Fatal("nondeterministic")
	}
	view, e := Present(a.Body, in.Now)
	if e != nil || len(view.Profiles) != 5 {
		t.Fatal("preview", e)
	}
	original, _ := importerObject(in.Sources[0].Normalized)
	actual, _ := importerObject(a.Body)
	if !bytes.Equal(raw(original["network"]), raw(actual["network"])) {
		t.Fatal("network rewritten")
	}
	cs := original["connections"].([]any)
	as := actual["connections"].([]any)
	for _, c := range cs {
		c := c.(map[string]any)
		found := false
		for _, ac := range as {
			ac := ac.(map[string]any)
			if ac["id"] == QualifiedID("fixture", c["id"].(string)) {
				found = true
				if !bytes.Equal(raw(c["settings"]), raw(ac["settings"])) {
					t.Fatal("native rewritten")
				}
			}
		}
		if !found {
			t.Fatal("missing record")
		}
	}
	in.MaxVersion = 0
	if _, e = Build(in); e != ErrCapability {
		t.Fatal("version downgrade", e)
	}
}
func importerObject(b []byte) (map[string]any, error) {
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	e := d.Decode(&m)
	return m, e
}
func TestBlueprintConflictsAndBounds(t *testing.T) {
	cases := map[string]func(*Input){
		"dangling":   func(i *Input) { i.Blueprint.Locations[0].Members[0].ConnectionID = "absent" },
		"cross mode": func(i *Input) { i.Blueprint.Locations[0].Mode = "bypass" },
		"native auto invented": func(i *Input) {
			i.Blueprint.Locations[0].Members = []Member{{SourceID: "fixture", ConnectionID: "synthetic-fi-tcp"}}
			i.Blueprint.Locations[0].Kind = "auto"
			i.Blueprint.Locations[0].Selection = "native"
		},
		"missing policy authority": func(i *Input) { delete(i.Blueprint.Routing, "vpn") },
		"server policy field":      func(i *Input) { i.Blueprint.Routing["server"] = PolicyChoice{Authority: "personal"} },
		"ambiguous custom":         func(i *Input) { i.Blueprint.Network.Value = json.RawMessage(`{}`) },
		"native rules discarded":   func(i *Input) { i.Blueprint.Routing["vpn"] = PolicyChoice{Authority: "personal"} },
		"oversize locations": func(i *Input) {
			for len(i.Blueprint.Locations) <= 64 {
				i.Blueprint.Locations = append(i.Blueprint.Locations, i.Blueprint.Locations[0])
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			in := blueprintFixture(t)
			change(&in)
			if a, e := Build(in); e == nil || len(a.Body) > 0 {
				t.Fatal("invalid blueprint accepted")
			}
		})
	}
}
func TestUnreachableRules(t *testing.T) {
	for _, pair := range [][4]string{{"domain_suffix", "example.com", "domain_exact", "a.example.com"}, {"ip_cidr", "10.0.0.0/8", "ip_cidr", "10.1.0.0/16"}, {"geosite", "ru", "geosite", "ru"}} {
		p := Object{"rules": []any{Object{"match": Object{"type": pair[0], "value": pair[1]}}, Object{"match": Object{"type": pair[2], "value": pair[3]}}}}
		if !unreachable(p) {
			t.Fatal("shadow not detected")
		}
	}
	if unreachable(Object{"rules": []any{Object{"match": Object{"type": "geosite", "value": "ru"}}, Object{"match": Object{"type": "domain_suffix", "value": "example.com"}}}}) {
		t.Fatal("unknown overlap guessed")
	}
}

func TestGeoAvailabilityUsesExactMobileIndex(t *testing.T) {
	original, e := os.ReadFile("../../../mobile/core/routing/assets/geodata-tags-v1.json")
	if e != nil || !bytes.Equal(original, geoIndex) {
		t.Fatal("geo inventory drift", e)
	}
	p := Object{"rules": []any{Object{"match": Object{"type": "geosite", "value": "not-installed-test-category"}}}}
	if availableGeo(p) {
		t.Fatal("unknown geodata accepted")
	}
	p = Object{"rules": []any{Object{"match": Object{"type": "geoip", "value": "ru"}}}}
	if !availableGeo(p) {
		t.Fatal("bundled category unavailable")
	}
}

func TestBlueprintPortableRoutesClientCapabilityAndSelectedRecords(t *testing.T) {
	in := blueprintFixture(t)
	in.Blueprint.Locations = []Location{{ID: "explicit-vpn", Title: "VPN group", Mode: "vpn", Kind: "auto", Selection: "first_working", Members: []Member{{SourceID: "fixture", ConnectionID: "synthetic-fi-tcp"}, {SourceID: "fixture", ConnectionID: "synthetic-fi-grpc"}}}}
	in.Blueprint.Routing = map[string]PolicyChoice{"vpn": {Authority: "custom", Value: json.RawMessage(`{"id":"policy","title":"Custom policy","default_action":"tunnel","rules":[{"id":"exception","action":"tunnel","match":{"type":"domain_exact","value":"special.example.com"}},{"id":"base","action":"direct","match":{"type":"domain_suffix","value":"example.com"}}]}`)}}
	a, e := Build(in)
	if e != nil {
		t.Fatal(e)
	}
	view, e := Present(a.Body, in.Now)
	if e != nil || view.Version != 2 || len(view.Profiles) != 2 {
		t.Fatal("explicit selection or v2 lost", e)
	}
	in.MaxVersion = 1
	if _, e = Build(in); e != ErrCapability {
		t.Fatal("unsupported client accepted", e)
	}
	in.MaxVersion = 2
	in.Blueprint.Routing["vpn"] = PolicyChoice{Authority: "custom", Value: json.RawMessage(`{"id":"policy","title":"Shadowed","default_action":"tunnel","rules":[{"id":"base","action":"direct","match":{"type":"domain_suffix","value":"example.com"}},{"id":"exception","action":"tunnel","match":{"type":"domain_exact","value":"special.example.com"}}]}`)}
	if _, e = Build(in); e != ErrPolicyConflict {
		t.Fatal("unreachable exception accepted", e)
	}
}
