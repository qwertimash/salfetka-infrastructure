// B0 semantic-preservation spike. This is intentionally test-only: input validation,
// general imports and a production compiler belong to B5/B6, not this prototype.
package compatibility

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type object = map[string]json.RawMessage
type request struct {
	Lab struct {
		Profiles []struct {
			ID       string          `json:"id"`
			Engine   string          `json:"engine"`
			Settings json.RawMessage `json:"settings"`
		} `json:"profiles"`
		ExpiresAt json.RawMessage `json:"expires_at"`
		DNS       json.RawMessage `json:"dns_servers"`
		Probe     json.RawMessage `json:"probe"`
	} `json:"lab"`
	Mapping struct {
		ID           json.RawMessage `json:"id"`
		Revision     json.RawMessage `json:"revision"`
		Subscription json.RawMessage `json:"subscription"`
		Locations    json.RawMessage `json:"locations"`
		NativeIDs    []string        `json:"native_connection_ids"`
	} `json:"mapping"`
	Native           map[string]object `json:"native"`
	Version          int               `json:"version"`
	TransportOnlyIDs []string          `json:"transport_only_ids"`
	Routing          json.RawMessage   `json:"routing"`
}

func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic("invalid synthetic fixture")
	}
	return b
}

// preserve assembles already-validated, frozen input. Native policy is opaque;
// it never infers countries/Auto/DNS or invents paid expiry or traffic counters.
func preserve(input []byte) ([]byte, error) {
	var in request
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, errors.New("fixture_json")
	}
	if in.Version != 1 && in.Version != 2 {
		return nil, errors.New("fixture_version")
	}
	records := []object{}
	seen := map[string]bool{}
	for _, p := range in.Lab.Profiles {
		if seen[p.ID] {
			return nil, errors.New("duplicate_record")
		}
		seen[p.ID] = true
		records = append(records, object{"id": raw(p.ID), "engine": raw(p.Engine), "settings": p.Settings})
	}
	native := map[string]bool{}
	for _, id := range in.Mapping.NativeIDs {
		config, ok := in.Native[id]
		if !ok || seen[id] {
			return nil, errors.New("native_record_missing_or_collision")
		}
		seen[id], native[id] = true, true
		delete(config, "remarks")
		delete(config, "meta")
		delete(config, "remnawave")
		records = append(records, object{"id": raw(id), "engine": raw("xray"), "settings": raw(object{"xray_config": raw(config)})})
	}
	roles := map[string]bool{}
	for _, id := range in.TransportOnlyIDs {
		if in.Version != 2 || !native[id] || roles[id] {
			return nil, errors.New("transport_only_record")
		}
		roles[id] = true
	}
	for _, record := range records {
		var id string
		if err := json.Unmarshal(record["id"], &id); err != nil {
			return nil, errors.New("fixture_id")
		}
		if roles[id] {
			record["routing_role"] = raw("transport_only")
		}
	}
	result := object{"format": raw("salfetka.subscription"), "version": raw(in.Version),
		"id": in.Mapping.ID, "revision": in.Mapping.Revision, "subscription": in.Mapping.Subscription,
		"valid_until": in.Lab.ExpiresAt, "locations": in.Mapping.Locations, "connections": raw(records),
		"network": raw(object{"dns_servers": in.Lab.DNS, "probe": in.Lab.Probe})}
	if in.Routing != nil {
		if in.Version != 2 || bytes.Equal(in.Routing, []byte("null")) {
			return nil, errors.New("fixture_routing")
		}
		result["routing"] = in.Routing
	}
	return json.Marshal(result)
}

func semantic(t *testing.T, data []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var result any
	if err := d.Decode(&result); err != nil {
		t.Fatal("invalid fixture JSON")
	}
	return result
}

func TestCompleteGoldenSet(t *testing.T) {
	data, err := os.ReadFile("fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SourceHashes map[string]string `json:"source_hashes"`
		Cases        []struct {
			Name     string
			Input    json.RawMessage
			Expected json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for name, expected := range fixture.SourceHashes {
		source, err := os.ReadFile(filepath.Join("../../..", name))
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(source)
		if hex.EncodeToString(actual[:]) != expected {
			t.Fatalf("source drift: %s", name)
		}
	}
	if len(fixture.Cases) != 7 {
		t.Fatal("incomplete golden fixture set")
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			before := bytes.Clone(tc.Input)
			actual, err := preserve(tc.Input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(semantic(t, actual), semantic(t, tc.Expected)) {
				t.Fatal("semantic preservation mismatch (payload intentionally omitted)")
			}
			repeated, err := preserve(tc.Input)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, repeated) || !bytes.Equal(before, tc.Input) {
				t.Fatal("non-deterministic or mutated source")
			}
		})
	}
}
