package httpapi

import (
	"net/http/httptest"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
)

func TestHeartbeatOptionalSiteStrictNestedDecoding(t *testing.T) {
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{`{"schema_version":1,"node_id":"fixture"}`, true},
		{`{"site":{"domain":"node.example.com","state":"unavailable","expires_at":"0001-01-01T00:00:00Z"}}`, true},
		{`{"site":{"domain":"node.example.com","domain":"other.example.com","state":"unavailable"}}`, false},
		{`{"site":{"domain":"node.example.com","private_key":"must-not-be-accepted"}}`, false},
		{`{"site":{"domain":"node.example.com"},"unknown":true}`, false},
	} {
		r := httptest.NewRequest("POST", "/api/v1/node/heartbeat", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		var value nodewire.HeartbeatRequest
		if decodeNodeDocument(w, r, &value) != tc.ok {
			t.Fatalf("unexpected decode result: %s", tc.body)
		}
	}
}
