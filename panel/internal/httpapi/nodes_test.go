package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/secrets"
)

func nodeFixture(t *testing.T) (fixture, *nodes.Authority) {
	f := newFixture(t)
	bundle, err := nodes.GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := nodes.LoadAuthority(bundle)
	if err != nil {
		t.Fatal(err)
	}
	vault, _ := secrets.New(bytes.Repeat([]byte{5}, 32))
	f.handler.(*api).nodes = nodes.New(f.pool, vault, authority)
	f.handler.(*api).config.NodeAuthority = authority
	return f, authority
}
func TestNodeAdminRBACStrictJSONAndSecretIsolation(t *testing.T) {
	f, _ := nodeFixture(t)
	owner := f.owner(t)
	ctx := context.Background()
	route := "/api/v1/nodes"
	status(t, call(f.handler, "GET", route, "", nil, nil), 401)
	status(t, call(f.handler, "POST", route, `{"name":"Node fixture"}`, &owner, map[string]string{"Idempotency-Key": "node-origin-000001", "Origin": "https://evil.invalid"}), 403)
	for _, body := range []string{`{"name":"Node fixture","name":"Duplicate"}`, `{"name":"Node fixture","extra":1}`, `{"name":null}`, `{}`} {
		status(t, call(f.handler, "POST", route, body, &owner, map[string]string{"Idempotency-Key": "node-strict-000001"}), 400)
	}
	w := call(f.handler, "POST", route, `{"name":"Node fixture"}`, &owner, map[string]string{"Idempotency-Key": "node-create-000001"})
	status(t, w, 201)
	var n nodes.Node
	if err := json.Unmarshal(w.Body.Bytes(), &n); err != nil {
		t.Fatal(err)
	}
	endpoint := route + "/" + n.ID + "/enrollment"
	headers := accessHeaders(n.Revision, "node-enrollment-0001")
	w = call(f.handler, "POST", endpoint, `{}`, &owner, headers)
	status(t, w, 201)
	var created nodes.EnrollmentCreated
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	retry := call(f.handler, "POST", endpoint, `{}`, &owner, headers)
	status(t, retry, 201)
	if retry.Header().Get("Idempotent-Replayed") != "true" || retry.Body.String() != w.Body.String() {
		t.Fatal("admin enrollment retry changed secret")
	}
	for _, path := range []string{route, route + "/" + n.ID, "/api/v1/audit"} {
		read := call(f.handler, "GET", path, "", &owner, nil)
		status(t, read, 200)
		if strings.Contains(read.Body.String(), created.Enrollment.Token) || strings.Contains(read.Body.String(), "token_hash") || strings.Contains(read.Body.String(), "ciphertext") {
			t.Fatal("secret in safe view")
		}
	}
	sessions := []identity.Session{owner}
	for _, role := range []identity.Role{identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor} {
		u, err := f.store.CreateAdmin(ctx, owner.Token, "node_"+string(role), testPassword, role)
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.Login(ctx, u.Username, testPassword, "local")
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	for _, s := range sessions {
		t.Run(string(s.User.Role), func(t *testing.T) {
			status(t, call(f.handler, "GET", route, "", &s, nil), 200)
			want := 403
			if s.User.Role == identity.Owner || s.User.Role == identity.InfrastructureOperator {
				want = 201
			}
			status(t, call(f.handler, "POST", route, `{"name":"Role node"}`, &s, map[string]string{"Idempotency-Key": "node-role-create-0001"}), want)
		})
	}
	status(t, call(f.handler, "POST", route+"/"+n.ID+"/revoke", `{}`, &owner, accessHeaders(n.Revision, "node-stale-revoke-0001")), 412)
	for _, s := range []string{created.Enrollment.Token, owner.Token, owner.CSRFToken, "Node fixture"} {
		if strings.Contains(f.logs.String(), s) {
			t.Fatal("node secret in logs")
		}
	}
}
func TestNodeMachineActualTLSRequiresVerifiedClientAndChecksRevocationEachRequest(t *testing.T) {
	f, authority := nodeFixture(t)
	owner := f.owner(t)
	ctx := context.Background()
	var n nodes.Node
	var enrollment nodes.EnrollmentCreated
	err := f.store.WithAuthorizedSession(ctx, owner.Token, []identity.Role{identity.Owner}, func(tx pgx.Tx, current identity.Session) error {
		var err error
		n, _, err = f.handler.(*api).nodes.CreateTx(ctx, tx, nodes.Mutation{ActorID: current.User.ID, Route: "create", Key: "tls-create-node-0001"}, "TLS node")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = f.store.WithAuthorizedSession(ctx, owner.Token, []identity.Role{identity.Owner}, func(tx pgx.Tx, current identity.Session) error {
		var err error
		enrollment, _, err = f.handler.(*api).nodes.EnrollmentTx(ctx, tx, nodes.Mutation{ActorID: current.User.ID, Route: "enroll", TargetID: n.ID, Revision: n.Revision, Key: "tls-enrollment-0001"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(f.handler)
	server.Config.ErrorLog = nil
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: authority.CertPool()}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	post := func(c *http.Client, path string, body any, want int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		resp, err := c.Post(server.URL+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal("local TLS request failed")
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		if resp.StatusCode != want {
			t.Fatalf("local TLS status %d want %d", resp.StatusCode, want)
		}
		return b
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	requestID, _ := database.NewID()
	request := nodewire.EnrollmentRequest{SchemaVersion: 1, NodeID: n.ID, Token: enrollment.Enrollment.Token, RequestID: requestID, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}
	malformed := request
	malformed.CSRPEM = "not a CSR"
	post(client, nodewire.EnrollmentPath, malformed, 400)
	raw := post(client, nodewire.EnrollmentPath, request, 200)
	var issued nodewire.EnrollmentResponse
	if err = json.Unmarshal(raw, &issued); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, post(client, nodewire.EnrollmentPath, request, 200)) {
		t.Fatal("machine HTTP lost-response retry changed cert")
	}
	boot, _ := database.NewID()
	hb := nodewire.HeartbeatRequest{SchemaVersion: 1, NodeID: n.ID, BootID: boot, Sequence: 1, Version: "test", Platform: "darwin", Arch: "arm64", Capabilities: []string{"heartbeat"}}
	post(client, nodewire.HeartbeatPath, hb, 401)
	// A valid browser session still cannot substitute for a node certificate.
	status(t, call(f.handler, "POST", nodewire.HeartbeatPath, fmt.Sprintf(`{"schema_version":1,"node_id":%q,"boot_id":%q,"sequence":1,"version":"test","platform":"darwin","arch":"arm64","capabilities":["heartbeat"]}`, n.ID, boot), &owner, nil), 401)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	pair, err := tls.X509KeyPair([]byte(issued.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if err != nil {
		t.Fatal(err)
	}
	mtlsTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}
	mtls := &http.Client{Transport: mtlsTransport, Timeout: 5 * time.Second}
	defer mtlsTransport.CloseIdleConnections()
	first := post(mtls, nodewire.HeartbeatPath, hb, 200)
	if !bytes.Equal(first, post(mtls, nodewire.HeartbeatPath, hb, 200)) {
		t.Fatal("heartbeat receipt replay")
	}
	wrong := hb
	wrong.NodeID, _ = database.NewID()
	post(mtls, nodewire.HeartbeatPath, wrong, 401)
	invalid := hb
	invalid.Capabilities = []string{"vpn_running"}
	post(mtls, nodewire.HeartbeatPath, invalid, 400)
	err = f.store.WithAuthorizedSession(ctx, owner.Token, []identity.Role{identity.Owner}, func(tx pgx.Tx, current identity.Session) error {
		node, err := f.handler.(*api).nodes.GetTx(ctx, tx, n.ID)
		if err != nil {
			return err
		}
		_, _, err = f.handler.(*api).nodes.RevokeTx(ctx, tx, nodes.Mutation{ActorID: current.User.ID, Route: "revoke", TargetID: n.ID, Revision: node.Revision, Key: "tls-revocation-0001"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	hb.Sequence++
	post(mtls, nodewire.HeartbeatPath, hb, 401)
	post(client, nodewire.EnrollmentPath, request, 403)
	for _, secret := range []string{enrollment.Enrollment.Token, request.CSRPEM, string(pkcs8)} {
		if strings.Contains(f.logs.String(), secret) {
			t.Fatal("machine credential leaked to logs")
		}
	}
}
