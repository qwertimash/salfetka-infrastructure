package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

func TestVPNHTTPConfigRolesAndRealMTLSIssuance(t *testing.T) {
	f, authority := nodeFixture(t)
	owner := f.owner(t)
	ctx := context.Background()
	raw, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(raw)
	f.handler.(*api).nodes.Signer = signer
	w := call(f.handler, "POST", "/api/v1/nodes", `{"name":"VPN HTTP fixture"}`, &owner, map[string]string{"Idempotency-Key": "vpn-node-create-000001"})
	status(t, w, 201)
	var n nodes.Node
	json.Unmarshal(w.Body.Bytes(), &n)
	w = call(f.handler, "POST", "/api/v1/nodes/"+n.ID+"/enrollment", `{}`, &owner, accessHeaders(n.Revision, "vpn-node-enrollment-001"))
	status(t, w, 201)
	var created nodes.EnrollmentCreated
	json.Unmarshal(w.Body.Bytes(), &created)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	requestID, _ := database.NewID()
	issued, _, e := f.handler.(*api).nodes.Enroll(ctx, nodewire.EnrollmentRequest{SchemaVersion: 1, NodeID: n.ID, Token: created.Enrollment.Token, RequestID: requestID, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
	if e != nil {
		t.Fatal(e)
	}
	read := call(f.handler, "GET", "/api/v1/nodes/"+n.ID, "", &owner, nil)
	status(t, read, 200)
	json.Unmarshal(read.Body.Bytes(), &n)
	installation, _ := database.NewID()
	route := "/api/v1/nodes/" + n.ID + "/vpn"
	body := `{"installation_id":"` + installation + `","group_id":"` + access.DefaultGroupID + `","enabled":true}`
	headers := accessHeaders(n.Revision, "vpn-http-config-000001")
	status(t, call(f.handler, "POST", route, body, nil, headers), 401)
	for _, role := range []identity.Role{identity.AccessOperator, identity.Support, identity.Auditor} {
		u, e := f.store.CreateAdmin(ctx, owner.Token, "vpn_"+string(role), testPassword, role)
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.store.Login(ctx, u.Username, testPassword, "local")
		if e != nil {
			t.Fatal(e)
		}
		status(t, call(f.handler, "POST", route, body, &session, headers), 403)
	}
	status(t, call(f.handler, "POST", route, strings.Replace(body, `,"enabled":true`, "", 1), &owner, headers), 400)
	status(t, call(f.handler, "POST", route+"?extra=1", body, &owner, headers), 400)
	w = call(f.handler, "POST", route, body, &owner, headers)
	status(t, w, 202)
	retry := call(f.handler, "POST", route, body, &owner, headers)
	status(t, retry, 202)
	if retry.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("operator retry")
	}
	status(t, call(f.handler, "POST", nodewire.VPNDesiredPath, `{}`, &owner, nil), 401)
	server := httptest.NewUnstartedServer(f.handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: authority.CertPool()}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pair, e := tls.X509KeyPair([]byte(issued.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if e != nil {
		t.Fatal(e)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := nodes.VPNFetch{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, EngineEpoch: strings.Repeat("d", 32)}
	encoded, _ := json.Marshal(request)
	post := func(path string, data []byte, want int) []byte {
		t.Helper()
		resp, e := client.Post(server.URL+path, "application/json", bytes.NewReader(data))
		if e != nil {
			t.Fatal("TLS request")
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("status %d expected %d", resp.StatusCode, want)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("private response cache")
		}
		return b
	}
	post(nodewire.VPNDesiredPath+"?extra=1", encoded, 400)
	post(nodewire.VPNDesiredPath, []byte(`{"schema_version":1,"schema_version":1}`), 400)
	first := post(nodewire.VPNDesiredPath, encoded, 200)
	if !bytes.Equal(first, post(nodewire.VPNDesiredPath, encoded, 200)) {
		t.Fatal("machine retry changed policy")
	}
	var desired nodewire.VPNDesired
	json.Unmarshal(first, &desired)
	pub, _ := nodecontrol.LoadPublicKey(signer.PublicPEM())
	policy, e := nodecontrol.VerifyVPN(pub, *desired.Policy)
	if e != nil || len(policy.Grants) != 0 || policy.EngineEpoch != request.EngineEpoch {
		t.Fatal("deny-all signed policy")
	}

	now := time.Now().UTC()
	report := nodewire.VPNReport{Receipt: nodewire.VPNReceipt{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, Generation: policy.Generation, PolicySHA256: nodecontrol.VPNHash(*desired.Policy), Status: "applied", CompletedAt: now, Usage: []nodewire.VPNUsage{}}, EngineEpoch: request.EngineEpoch, Sequence: 1, ObservedAt: now, Usage: []nodewire.VPNUsage{}}
	reportJSON, _ := json.Marshal(report)
	status(t, call(f.handler, "POST", nodewire.VPNReceiptsPath, string(reportJSON), &owner, nil), 401)
	post(nodewire.VPNReceiptsPath, reportJSON, 200)
	post(nodewire.VPNReceiptsPath, reportJSON, 200)
	post(nodewire.VPNReceiptsPath, bytes.Replace(reportJSON, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), 400)
	post(nodewire.VPNReceiptsPath, bytes.Replace(reportJSON, []byte(`"schema_version":1`), []byte(`"schema_version":1,"surprise":true`), 1), 400)
	observed := call(f.handler, "GET", route, "", &owner, nil)
	status(t, observed, 200)
	var observedStatus nodes.VPNStatus
	if json.Unmarshal(observed.Body.Bytes(), &observedStatus) != nil || observedStatus.State != "applied" {
		t.Fatal("observed report unavailable")
	}
	exportRoute := "/api/v1/access/users/" + n.ID + "/devices/" + installation + "/vpn-config"
	exportBody := `{"node_id":"` + n.ID + `"}`
	status(t, call(f.handler, "POST", exportRoute, exportBody, &owner, map[string]string{"X-CSRF-Token": ""}), 403)
	status(t, call(f.handler, "POST", exportRoute, exportBody, &owner, nil), 409)
	for _, role := range []identity.Role{identity.InfrastructureOperator, identity.Support, identity.Auditor} {
		name := "export_" + string(role)
		u, e := f.store.CreateAdmin(ctx, owner.Token, name, testPassword, role)
		if e != nil {
			t.Fatal(e)
		}
		session, e := f.store.Login(ctx, u.Username, testPassword, "local")
		if e != nil {
			t.Fatal(e)
		}
		status(t, call(f.handler, "POST", exportRoute, exportBody, &session, nil), 403)
	}
	// The bypass coordinator is machine-only, bound to a verified live cert.
	status(t, call(f.handler, "POST", nodewire.BypassSessionPath, `{}`, &owner, nil), 401)
	nonce, _ := database.NewID()
	fence := nodewire.BypassRequest{SchemaVersion: 1, NodeID: n.ID, InstallationID: installation, EngineEpoch: request.EngineEpoch, Nonce: nonce, Operation: "fence", PreviousEngineStopped: true}
	fenceJSON, _ := json.Marshal(fence)
	post(nodewire.BypassSessionPath, fenceJSON, 409) // ordinary VPN cannot opt in implicitly
	if _, e = f.pool.Exec(ctx, `UPDATE nodes_vpn_installations SET endpoint='{"backend":"olcrtc","account_session":true}' WHERE node_id=$1`, n.ID); e != nil {
		t.Fatal(e)
	}
	post(nodewire.BypassSessionPath+"?extra=1", fenceJSON, 400)
	post(nodewire.BypassSessionPath, []byte(`{"schema_version":1,"schema_version":1}`), 400)
	var fenced nodewire.BypassResponse
	if json.Unmarshal(post(nodewire.BypassSessionPath, fenceJSON, 200), &fenced) != nil || fenced.State != "fenced" || fenced.Nonce != nonce {
		t.Fatal("fence response binding")
	}
	if _, e = f.pool.Exec(ctx, "UPDATE nodes_registry SET state='revoked' WHERE id=$1", n.ID); e != nil {
		t.Fatal(e)
	}
	post(nodewire.VPNDesiredPath, encoded, 401)
	post(nodewire.BypassSessionPath, fenceJSON, 401)
}
