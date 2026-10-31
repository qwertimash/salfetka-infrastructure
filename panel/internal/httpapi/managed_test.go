package httpapi

import (
	"context"
	"encoding/json"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"strings"
	"testing"
)

func TestManagedServerHTTPBatchPublicViewRolesAndRetry(t *testing.T) {
	f, _ := nodeFixture(t)
	owner := f.owner(t)
	w := call(f.handler, "POST", "/api/v1/servers", `{"name":"Managed fixture","address":"203.0.113.10","domain":"pol.example.com"}`, &owner, accessHeaders(0, "managed-server-http-0001"))
	status(t, w, 200)
	var server nodes.Server
	json.Unmarshal(w.Body.Bytes(), &server)
	route := "/api/v1/managed/servers/" + server.ID
	status(t, call(f.handler, "GET", "/api/v1/managed/templates", "", &owner, nil), 200)
	w = call(f.handler, "POST", route+"/node", `{}`, &owner, accessHeaders(0, "managed-register-http-0001"))
	status(t, w, 200)
	var node nodes.Node
	json.Unmarshal(w.Body.Bytes(), &node)
	input := `{"connections":[{"name":"Reality fixture","group_id":"00000000-0000-4000-8000-000000000001","enabled":true,"configuration":{"public":{"template":"vless-tcp-reality","version":1,"host":"vpn.example.com","listen_ip":"0.0.0.0","port":0,"server_name":"target.example.com","reality_target":"target.example.com:443"},"private":{}}}]}`
	batchRoute := "/api/v1/managed/nodes/" + node.ID + "/connections"
	w = call(f.handler, "POST", batchRoute, input, &owner, accessHeaders(node.Revision, "managed-batch-http-0001"))
	status(t, w, 200)
	var batch nodes.ManagedBatch
	json.Unmarshal(w.Body.Bytes(), &batch)
	again := call(f.handler, "POST", batchRoute, input, &owner, accessHeaders(node.Revision, "managed-batch-http-0001"))
	status(t, again, 200)
	if again.Body.String() != w.Body.String() {
		t.Fatal("lost-response retry changed batch")
	}
	if strings.Contains(w.Body.String(), "private_key") || strings.Contains(w.Body.String(), "key_pem") {
		t.Fatal("secret in batch response")
	}
	w = call(f.handler, "GET", route, "", &owner, nil)
	status(t, w, 200)
	var detail nodes.ManagedServer
	if json.Unmarshal(w.Body.Bytes(), &detail) != nil || len(detail.Connections) != 1 || detail.Node.ID != node.ID || detail.Connections[0].RuntimeState != "pending" {
		t.Fatal("managed view invalid")
	}
	if strings.Contains(w.Body.String(), "private_key") || strings.Contains(w.Body.String(), "key_pem") {
		t.Fatal("secret in list")
	}
	status(t, call(f.handler, "POST", "/api/v1/servers/"+server.ID+"/connections", `{"name":"duplicate physical"}`, &owner, accessHeaders(0, "managed-legacy-http-0001")), 409)
	status(t, call(f.handler, "POST", batchRoute, input, &owner, map[string]string{"Idempotency-Key": "managed-missing-csrf", "X-CSRF-Token": ""}), 403)
	if _, e := f.store.CreateAdmin(context.Background(), owner.Token, "managedsupport", testPassword, identity.Support); e != nil {
		t.Fatal(e)
	}
	support, e := f.store.Login(context.Background(), "managedsupport", testPassword, "managedsupport")
	if e != nil {
		t.Fatal(e)
	}
	status(t, call(f.handler, "GET", route, "", &support, nil), 200)
	status(t, call(f.handler, "POST", batchRoute, input, &support, accessHeaders(batch.NodeRevision, "managed-support-http-0001")), 403)
	f.handler.(*api).config.DeliveryOnly = true
	for _, path := range []string{route, "/api/v1/managed/templates", "/api/v1/node/connections/desired", "/api/v1/node/connections/receipts"} {
		status(t, call(f.handler, "GET", path, "", &owner, nil), 404)
	}
}
