package nodes

import (
	"encoding/json"
	"testing"
)

func TestVPNEndpointStrictPublicMetadata(t *testing.T) {
	good := `{"host":"vpn.example.invalid","port":14443,"server_name":"vpn.example.invalid"}`
	var endpoint VPNEndpoint
	if json.Unmarshal([]byte(good), &endpoint) != nil || !endpoint.Valid() {
		t.Fatal("valid endpoint")
	}
	for _, raw := range []string{`{"host":"a","host":"b","port":14443,"server_name":"a"}`, `{"host":"a","port":14443,"server_name":"a","private_key":"secret"}`, `{"host":"a","port":14443}`, `{"host":"a","port":14443,"server_name":"a","trusted_ca_pem":null}`} {
		if json.Unmarshal([]byte(raw), &endpoint) == nil {
			t.Fatal("ambiguous endpoint accepted")
		}
	}
	for _, host := range []string{"https://example.invalid", "user@example.invalid", "a/b", "a\nheader", "-bad.invalid", "a..b"} {
		if (VPNEndpoint{Host: host, Port: 14443, ServerName: "vpn.invalid"}).Valid() {
			t.Fatal("invalid endpoint host")
		}
	}
}
