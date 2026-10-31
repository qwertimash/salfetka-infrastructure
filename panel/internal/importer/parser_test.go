package importer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestURIOracleMatchesExistingMobileParser(t *testing.T) {
	b, e := os.ReadFile("testdata/uris.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures struct {
		OracleSHA256 string `json:"oracle_sha256"`
		Cases        []struct {
			Name     string
			Input    string
			Settings json.RawMessage
		}
	}
	if json.Unmarshal(b, &fixtures) != nil || len(fixtures.Cases) != 10 {
		t.Fatal("incomplete URI oracle")
	}
	oracle, e := os.ReadFile("../../../mobile/scripts/subscription_catalog.py")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(oracle)
	if hex.EncodeToString(h[:]) != fixtures.OracleSHA256 {
		t.Fatal("oracle changed")
	}
	for _, c := range fixtures.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r, e := Parse([]byte(c.Input), time.Now())
			if e != nil {
				t.Fatal(e)
			}
			v, _ := Decode(r.Normalized)
			settings := obj(arr(v)[0])["settings"]
			want, _ := Decode(c.Settings)
			if !reflect.DeepEqual(settings, want) {
				t.Fatal("URI semantics differ from mobile oracle")
			}
		})
	}
}

const testURI = "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?security=tls&type=xhttp&path=%2Ftest&mode=auto#test"

func TestMobileGoldenManifestsPreserveAllSemantics(t *testing.T) {
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
	if json.Unmarshal(b, &f) != nil || len(f.Cases) != 7 {
		t.Fatal("fixture set")
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r, e := Parse(c.Expected, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			if e != nil {
				t.Fatal(e, compileError)
			}
			v, _ := Decode(c.Expected)
			got, _ := Decode(r.Normalized)
			if !reflect.DeepEqual(v, got) || !bytes.Equal(r.Original, c.Expected) || r.Preview.PublicationReady {
				t.Fatal("semantic loss")
			}
			preview, _ := json.Marshal(r.Preview)
			for _, secret := range []string{"key_hex", "settings", "secret", "outbounds"} {
				if bytes.Contains(preview, []byte(secret)) {
					t.Fatal("private preview")
				}
			}
		})
	}
	for i, path := range []string{"subscription-manifest.schema.json", "subscription-manifest-v2.schema.json"} {
		source, e := os.ReadFile("../../../mobile/contracts/" + path)
		if e != nil {
			t.Fatal(e)
		}
		copy, _ := schemas.ReadFile("schemas/v" + string(rune('1'+i)) + ".json")
		if !bytes.Equal(source, copy) {
			t.Fatal("schema drift")
		}
	}
}
func TestURIsAndCompleteSubscription(t *testing.T) {
	for _, uri := range []string{testURI, strings.Replace(testURI, "type=xhttp&path=%2Ftest&mode=auto", "type=tcp", 1), "hy2://synthetic-auth@vpn.example.com?sni=vpn.example.com"} {
		r, e := Parse([]byte(uri), time.Now())
		if e != nil || len(r.Preview.Profiles) != 1 {
			t.Fatalf("uri: %v", e)
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(uri))
		b, e := Parse([]byte(encoded), time.Now())
		if e != nil || !bytes.Equal(r.Normalized, b.Normalized) {
			t.Fatal("base64 mismatch")
		}
	}
	r, e := Parse([]byte(testURI+"\n"+testURI), time.Now())
	if e != nil || len(r.Preview.Profiles) != 2 || r.Preview.Profiles[0].ID == r.Preview.Profiles[1].ID {
		t.Fatal("name collision merged records")
	}
	for _, bad := range []string{testURI + "\nss://not-supported", strings.Replace(testURI, "security=tls", "security=none", 1), strings.Replace(testURI, "security=tls", "security=tls&security=tls", 1), strings.Replace(testURI, "security=tls", "security=tls&allowInsecure=1", 1), strings.Replace(testURI, "type=xhttp", "type=xhttp&unknown=kept?", 1), strings.Repeat(testURI+"\n", 33)} {
		if _, e := Parse([]byte(bad), time.Now()); e == nil {
			t.Fatal("bad source accepted")
		}
	}
}
func TestStrictJSONAndNativePolicy(t *testing.T) {
	for _, bad := range []string{`{"outbounds":[],"outbounds":[]}`, `{"x":"\ud800"}`, `{"x":"\udc00"}`, `{"x":"\ud800\u0041"}`, `{"x":NaN}`, `{"x":1} {}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), string([]byte{'"', 0xff, '"'})} {
		if _, e := Decode([]byte(bad)); e == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	if _, e := Decode([]byte(`{"x":"\ud83d\ude00"}`)); e != nil {
		t.Fatal(e)
	}
	good := `{"remarks":"private title","outbounds":[{"protocol":"vless","tag":"proxy","settings":{"kept_unknown_field":true}}],"routing":{"rules":[{"network":"tcp,udp","outboundTag":"proxy"}]},"dns":{"servers":["1.1.1.1"]}}`
	r, e := Parse([]byte(good), time.Now())
	if e != nil || !r.Preview.Profiles[0].DNS || !bytes.Contains(r.Normalized, []byte("kept_unknown_field")) || bytes.Contains(r.Normalized, []byte("private title")) {
		t.Fatal("native policy preservation")
	}
	for _, bad := range []string{strings.Replace(good, `"kept_unknown_field":true`, `"allowInsecure":true`, 1), strings.Replace(good, `"kept_unknown_field":true`, `"certificateFile":"/private/path"`, 1), strings.Replace(good, `"outboundTag":"proxy"`, `"outboundTag":"missing"`, 1), strings.Replace(good, `"remarks":"private title"`, `"api":{}`, 1)} {
		if _, e := Parse([]byte(bad), time.Now()); e == nil {
			t.Fatal("unsafe native accepted")
		}
	}
}
func TestManifestMutationFailsClosed(t *testing.T) {
	b, _ := os.ReadFile("../../tests/compatibility/fixtures.json")
	var f struct {
		Cases []struct{ Expected json.RawMessage }
	}
	json.Unmarshal(b, &f)
	for _, mutate := range []func(object){
		func(m object) { m["valid_until"] = "2020-01-01T00:00:00Z" },
		func(m object) { m["valid_until"] = "2099-02-30T00:00:00Z" },
		func(m object) {
			connections := arr(m["connections"])
			m["connections"] = append(connections, connections[0])
		},
		func(m object) { obj(arr(m["locations"])[0])["connection_ids"] = []any{"missing"} },
		func(m object) {
			obj(m["subscription"])["traffic"] = []any{object{"scope": "subscription"}, object{"scope": "vpn"}}
		},
		func(m object) {
			obj(m["subscription"])["traffic"] = []any{object{"scope": "subscription", "upload_bytes": json.Number("18446744073709551616")}}
		},
	} {
		v, _ := Decode(f.Cases[0].Expected)
		m := obj(v)
		mutate(m)
		if _, e := Parse(canonical(m), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); e == nil {
			t.Fatal("bad manifest accepted")
		}
	}
	v, _ := Decode(f.Cases[0].Expected)
	m := obj(v)
	obj(m["subscription"])["traffic"] = []any{object{"scope": "subscription", "upload_bytes": json.Number("18446744073709551615")}}
	if _, e := Parse(canonical(m), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); e != nil {
		t.Fatal("uint64 precision", e)
	}
}
func FuzzParseNeverLeaksOrPanics(f *testing.F) {
	b, e := os.ReadFile("../../tests/compatibility/fixtures.json")
	if e != nil {
		f.Fatal(e)
	}
	var fixtures struct {
		Cases []struct{ Expected json.RawMessage }
	}
	if json.Unmarshal(b, &fixtures) != nil {
		f.Fatal("fixtures")
	}
	for _, c := range fixtures.Cases {
		f.Add([]byte(c.Expected))
	}
	for _, s := range []string{testURI, `{"outbounds":[]}`, `[]`, `{"format":"salfetka.subscription","version":2}`, `{"outbounds":[{"protocol":"vless"}],"inbounds":[null]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, e := Parse(b, time.Unix(0, 0))
		if e != nil {
			if _, ok := e.(Error); !ok || len(e.Error()) > 64 || !strings.HasPrefix(e.Error(), "source_") {
				t.Fatal("unbounded error")
			}
		}
	})
}
