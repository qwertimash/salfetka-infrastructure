package nodeagent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
)

type bypassRoundTrip func(*http.Request) (*http.Response, error)

func (f bypassRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestBypassResponseBindingAndFreshNonce(t *testing.T) {
	for _, bad := range []string{"", "nonce", "epoch", "installation", "operation", "ttl"} {
		t.Run(bad, func(t *testing.T) {
			seen := ""
			a := &Agent{cfg: Config{PanelURL: "https://example.invalid"}, state: localState{NodeID: testNode, Enrollment: &nodewire.EnrollmentResponse{}}, client: &http.Client{Transport: bypassRoundTrip(func(r *http.Request) (*http.Response, error) {
				var q nodewire.BypassRequest
				if e := json.NewDecoder(r.Body).Decode(&q); e != nil {
					t.Fatal(e)
				}
				if q.Nonce == "" || q.Nonce == seen {
					t.Fatal("nonce reused")
				}
				seen = q.Nonce
				out := nodewire.BypassResponse{SchemaVersion: 1, NodeID: q.NodeID, InstallationID: q.InstallationID, EngineEpoch: q.EngineEpoch, Operation: q.Operation, Nonce: q.Nonce}
				switch bad {
				case "nonce":
					out.Nonce = "stale"
				case "epoch":
					out.EngineEpoch = "stale"
				case "installation":
					out.InstallationID = "other"
				case "operation":
					out.Operation = "renew"
				case "ttl":
					out.RemainingMS = 30001
				}
				b, _ := json.Marshal(out)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
			})}}
			for i := 0; i < 2; i++ {
				_, e := a.BypassSession(context.Background(), nodewire.BypassRequest{Operation: "claim", InstallationID: testNode, EngineEpoch: strings.Repeat("a", 32)})
				if bad == "" && e != nil {
					t.Fatal(e)
				}
				if bad != "" && e == nil {
					t.Fatal("unbound response accepted")
				}
			}
		})
	}
}
