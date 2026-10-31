package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

func TestNodeControlHTTPRoleCASAndMachineReceiptStrictness(t *testing.T) {
	f, _ := nodeFixture(t)
	owner := f.owner(t)
	raw, _ := nodecontrol.GenerateSigner()
	signer, e := nodecontrol.LoadSigner(raw)
	if e != nil {
		t.Fatal(e)
	}
	f.handler.(*api).nodes.Signer = signer
	w := call(f.handler, "POST", "/api/v1/nodes", `{"name":"Control fixture"}`, &owner, map[string]string{"Idempotency-Key": "control-create-node-0001"})
	status(t, w, 201)
	var n nodes.Node
	json.Unmarshal(w.Body.Bytes(), &n)
	w = call(f.handler, "POST", "/api/v1/nodes/"+n.ID+"/enrollment", `{}`, &owner, accessHeaders(n.Revision, "control-enroll-node-0001"))
	status(t, w, 201)
	var enrollment nodes.EnrollmentCreated
	json.Unmarshal(w.Body.Bytes(), &enrollment)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	requestID, _ := database.NewID()
	issued, _, e := f.handler.(*api).nodes.Enroll(context.Background(), nodewire.EnrollmentRequest{SchemaVersion: 1, NodeID: n.ID, Token: enrollment.Enrollment.Token, RequestID: requestID, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	machine := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, testOrigin+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		return w
	}
	route := "/api/v1/nodes/" + n.ID
	config := route + "/config"
	read := route + "/control"
	status(t, call(f.handler, "GET", read, "", nil, nil), 401)
	status(t, call(f.handler, "GET", nodewire.DesiredPath+"?node_id="+n.ID, "", &owner, nil), 401)
	status(t, call(f.handler, "POST", nodewire.ReceiptsPath, `{}`, &owner, nil), 401)
	w = call(f.handler, "GET", route, "", &owner, nil)
	status(t, w, 200)
	json.Unmarshal(w.Body.Bytes(), &n)
	for _, bad := range []string{`{"heartbeat_interval_seconds":4}`, `{"heartbeat_interval_seconds":31}`, `{"heartbeat_interval_seconds":5,"heartbeat_interval_seconds":6}`, `{"heartbeat_interval_seconds":null}`, `{"heartbeat_interval_seconds":5,"extra":true}`} {
		status(t, call(f.handler, "POST", config, bad, &owner, accessHeaders(n.Revision, "control-invalid-00001")), 400)
	}
	h := accessHeaders(n.Revision, "control-origin-0001")
	h["Origin"] = "https://evil.invalid"
	status(t, call(f.handler, "POST", config, `{"heartbeat_interval_seconds":5}`, &owner, h), 403)
	h = accessHeaders(n.Revision, "control-csrf-0001")
	h["X-CSRF-Token"] = "bad"
	status(t, call(f.handler, "POST", config, `{"heartbeat_interval_seconds":5}`, &owner, h), 403)
	var created nodes.CommandCreated
	for _, role := range []identity.Role{identity.Owner, identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor} {
		session := owner
		if role != identity.Owner {
			u, e := f.store.CreateAdmin(context.Background(), owner.Token, "control_"+string(role), testPassword, role)
			if e != nil {
				t.Fatal(e)
			}
			session, e = f.store.Login(context.Background(), u.Username, testPassword, "local")
			if e != nil {
				t.Fatal(e)
			}
		}
		status(t, call(f.handler, "GET", read, "", &session, nil), 200)
		w = call(f.handler, "GET", route, "", &owner, nil)
		json.Unmarshal(w.Body.Bytes(), &n)
		h = accessHeaders(n.Revision, "control-role-command-0001")
		w = call(f.handler, "POST", config, `{"heartbeat_interval_seconds":5}`, &session, h)
		want := 403
		if role == identity.Owner || role == identity.InfrastructureOperator {
			want = 202
		}
		status(t, w, want)
		if want == 202 {
			retry := call(f.handler, "POST", config, `{"heartbeat_interval_seconds":5}`, &session, h)
			status(t, retry, 202)
			if retry.Body.String() != w.Body.String() || retry.Header().Get("Idempotent-Replayed") != "true" {
				t.Fatal("HTTP replay changed snapshot")
			}
			json.Unmarshal(w.Body.Bytes(), &created)
			status(t, call(f.handler, "POST", config, `{"heartbeat_interval_seconds":6}`, &session, h), 409)
			status(t, call(f.handler, "POST", config, `{"heartbeat_interval_seconds":5}`, &session, accessHeaders(n.Revision, "control-stale-command-0001")), 412)
		}
	}
	status(t, machine("GET", nodewire.DesiredPath+"?node_id="+n.ID+"&%zz", ""), 400)
	w = machine("GET", nodewire.DesiredPath+"?node_id="+n.ID, "")
	status(t, w, 200)
	var desired nodewire.DesiredResponse
	json.Unmarshal(w.Body.Bytes(), &desired)
	if desired.Command == nil || *desired.Command != created.Command {
		t.Fatal("machine desired differs")
	}
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	c, e := nodecontrol.Verify(pub, created.Command)
	if e != nil {
		t.Fatal(e)
	}
	r := nodewire.Receipt{SchemaVersion: 1, NodeID: n.ID, OperationID: c.OperationID, AuthorityEpoch: 1, Generation: c.Generation, CommandSHA256: nodecontrol.CommandHash(created.Command), Status: "applied", Config: &c.Payload, CompletedAt: c.CreatedAt}
	body, _ := json.Marshal(r)
	for _, bad := range []string{strings.Replace(string(body), `"heartbeat_interval_seconds":5`, `"heartbeat_interval_seconds":5,"heartbeat_interval_seconds":5`, 1), strings.Replace(string(body), `"status":"applied"`, `"status":"applied","status":"applied"`, 1), strings.Replace(string(body), `"heartbeat_interval_seconds":5`, `"heartbeat_interval_seconds":5,"unexpected":1`, 1), string(body) + "{}"} {
		status(t, machine("POST", nodewire.ReceiptsPath, bad), 400)
	}
	// A finite failure with a future reported wall clock remains acknowledgeable.
	r.Status = "failed"
	r.Config = nil
	r.ErrorCode = "clock_rollback"
	r.CompletedAt = time.Now().Add(time.Hour)
	body, _ = json.Marshal(r)
	w = machine("POST", nodewire.ReceiptsPath, string(body))
	status(t, w, 200)
	retry := machine("POST", nodewire.ReceiptsPath, string(body))
	status(t, retry, 200)
	if retry.Header().Get("Idempotent-Replayed") != "true" || retry.Body.String() != w.Body.String() {
		t.Fatal("receipt retry")
	}
	w = call(f.handler, "GET", read, "", &owner, nil)
	status(t, w, 200)
	var control nodes.Control
	json.Unmarshal(w.Body.Bytes(), &control)
	var observed nodewire.Receipt
	json.Unmarshal(control.Observed, &observed)
	if observed.Status != "failed" || observed.Config != nil {
		t.Fatal("failure claimed applied")
	}
	w = call(f.handler, "GET", route, "", &owner, nil)
	json.Unmarshal(w.Body.Bytes(), &n)
	status(t, call(f.handler, "POST", route+"/revoke", `{}`, &owner, accessHeaders(n.Revision, "control-revoke-00001")), 200)
	status(t, machine("GET", nodewire.DesiredPath+"?node_id="+n.ID, ""), 401)
	status(t, machine("POST", nodewire.ReceiptsPath, string(body)), 401)
}
