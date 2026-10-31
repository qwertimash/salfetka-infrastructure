package nodeagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"salfetka/panel/internal/nodewire"
	"testing"
	"time"
)

func TestManagedSlowConnectionDoesNotBlockAnother(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request nodewire.VPNFetch
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.NodeID == testNode {
			close(entered)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(nodewire.VPNDesired{SchemaVersion: 1, NodeID: request.NodeID, Policy: &nodewire.SignedVPNPolicy{}})
	}))
	defer server.Close()
	defer close(release)
	agent := &Agent{cfg: Config{PanelURL: server.URL}, client: server.Client(), state: localState{Enrollment: &nodewire.EnrollmentResponse{}}}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = agent.FetchConnectionVPN(context.Background(), nodewire.ConnectionDeployment{ID: testNode}, "epoch-a")
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("A did not enter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	secondDone := make(chan error, 1)
	go func() {
		_, e := agent.FetchConnectionVPN(ctx, nodewire.ConnectionDeployment{ID: "00000000-0000-4000-8000-000000000002"}, "epoch-b")
		secondDone <- e
	}()
	select {
	case e := <-secondDone:
		if e != nil {
			t.Fatal("B blocked behind A", e)
		}
	case <-ctx.Done():
		t.Fatal("B blocked behind A")
	}
	select {
	case <-firstDone:
		t.Fatal("A unexpectedly completed before release")
	default:
	}
}
