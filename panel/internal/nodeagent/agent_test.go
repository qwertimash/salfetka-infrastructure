package nodeagent

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
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"salfetka/panel/internal/nodewire"
)

const testNode = "00000000-0000-4000-8000-000000000001"

type fixture struct {
	t                         *testing.T
	mu                        sync.Mutex
	server                    *httptest.Server
	ca                        *x509.Certificate
	key                       ed25519.PrivateKey
	cfg                       Config
	enrollment                []nodewire.EnrollmentRequest
	heartbeats                []nodewire.HeartbeatRequest
	issued                    *nodewire.EnrollmentResponse
	receipts                  map[string]nodewire.HeartbeatResponse
	dropEnroll, dropHeartbeat bool
	status                    int
	redirect                  string
	mutate                    func(*nodewire.EnrollmentResponse)
	persistedBeforeRequest    bool
	verifiedHeartbeat         bool
	desired                   *nodewire.SignedCommand
	desiredCalls              int
	desiredStatus             int
	controlReceipts           []nodewire.Receipt
	dropReceipt               bool
	ackStatus                 int
	renewalCalls              int
	renewalResponse           *nodewire.EnrollmentResponse
	dropRenewal               bool
	shortCertificate          bool
	heartbeatTimes            []time.Time
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic node authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, ca: ca, key: key, receipts: map[string]nodewire.HeartbeatResponse{}}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven}
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	dir := t.TempDir()
	f.cfg = Config{StateDir: filepath.Join(dir, "state"), PanelURL: f.server.URL, CAFile: filepath.Join(dir, "server-ca.pem"), TokenFile: filepath.Join(dir, "token.json"), HeartbeatInterval: time.Second}
	mustWrite(t, f.cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}))
	// An expired local timestamp must not prevent recovering a committed issuance.
	b, _ := json.Marshal(enrollmentToken{NodeID: testNode, Token: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(-time.Hour)})
	mustWrite(t, f.cfg.TokenFile, b)
	return f
}
func (f *fixture) issue(request nodewire.EnrollmentRequest) (nodewire.EnrollmentResponse, error) {
	csr, err := parseCSR(request.CSRPEM)
	if err != nil {
		return nodewire.EnrollmentResponse{}, err
	}
	u, _ := url.Parse(nodewire.IdentityURIPrefix + request.NodeID)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: request.NodeID}, URIs: []*url.URL{u}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if f.shortCertificate {
		template.NotAfter = time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, csr.PublicKey, f.key)
	return nodewire.EnrollmentResponse{SchemaVersion: 1, NodeID: request.NodeID, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), AuthorityPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})), Serial: "2", ExpiresAt: template.NotAfter}, err
}
func dropResponse(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		conn.Close()
	}
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, 307)
		return
	}
	if f.status != 0 {
		http.Error(w, "synthetic SECRET response must never reach logs", f.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case nodewire.EnrollmentPath:
		var request nodewire.EnrollmentRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		f.enrollment = append(f.enrollment, request)
		raw, err := os.ReadFile(filepath.Join(f.cfg.StateDir, "state.json"))
		var state localState
		f.persistedBeforeRequest = err == nil && json.Unmarshal(raw, &state) == nil && state.RequestID == request.RequestID && state.CSRPEM == request.CSRPEM && state.PrivateKeyPEM != ""
		if f.issued == nil {
			response, err := f.issue(request)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			f.issued = &response
		}
		if f.dropEnroll {
			f.dropEnroll = false
			dropResponse(w)
			return
		}
		response := *f.issued
		if f.mutate != nil {
			f.mutate(&response)
		}
		json.NewEncoder(w).Encode(response)
	case nodewire.RenewalPath:
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			w.WriteHeader(401)
			return
		}
		var request nodewire.RenewalRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.PreviousSerial != r.TLS.PeerCertificates[0].SerialNumber.Text(16) {
			w.WriteHeader(400)
			return
		}
		f.renewalCalls++
		if f.renewalResponse == nil {
			f.shortCertificate = false
			response, err := f.issue(nodewire.EnrollmentRequest{SchemaVersion: 1, NodeID: request.NodeID, CSRPEM: request.CSRPEM})
			if err != nil {
				w.WriteHeader(500)
				return
			}
			// Reissue a distinct serial while preserving the fixture CA/key.
			cert, _ := certificate(response.CertificatePEM)
			cert.SerialNumber = big.NewInt(3)
			csr, _ := parseCSR(request.CSRPEM)
			der, err := x509.CreateCertificate(rand.Reader, cert, f.ca, csr.PublicKey, f.key)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			response.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			response.Serial = "3"
			f.renewalResponse = &response
		}
		if f.dropRenewal {
			f.dropRenewal = false
			dropResponse(w)
			return
		}
		response := *f.renewalResponse
		if f.mutate != nil {
			f.mutate(&response)
		}
		json.NewEncoder(w).Encode(response)
	case nodewire.HeartbeatPath:
		f.verifiedHeartbeat = r.TLS != nil && len(r.TLS.VerifiedChains) > 0
		if !f.verifiedHeartbeat {
			w.WriteHeader(403)
			return
		}
		var request nodewire.HeartbeatRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		f.heartbeats = append(f.heartbeats, request)
		f.heartbeatTimes = append(f.heartbeatTimes, time.Now())
		encoded, _ := json.Marshal(request)
		key := string(encoded)
		response, exists := f.receipts[key]
		if !exists {
			response = nodewire.HeartbeatResponse{SchemaVersion: 1, NodeID: request.NodeID, Sequence: request.Sequence, ReceivedAt: time.Now().UTC(), Status: "recorded", EngineState: "not_configured"}
			f.receipts[key] = response
		}
		if f.dropHeartbeat {
			f.dropHeartbeat = false
			dropResponse(w)
			return
		}
		json.NewEncoder(w).Encode(response)
	case nodewire.DesiredPath:
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Method != http.MethodGet || r.URL.Query().Get("node_id") != testNode {
			w.WriteHeader(403)
			return
		}
		f.desiredCalls++
		if f.desiredStatus != 0 {
			w.WriteHeader(f.desiredStatus)
			return
		}
		json.NewEncoder(w).Encode(nodewire.DesiredResponse{SchemaVersion: 1, NodeID: testNode, Command: f.desired})
	case nodewire.ReceiptsPath:
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Method != http.MethodPost {
			w.WriteHeader(403)
			return
		}
		if f.ackStatus != 0 {
			w.WriteHeader(f.ackStatus)
			return
		}
		var receipt nodewire.Receipt
		if json.NewDecoder(r.Body).Decode(&receipt) != nil {
			w.WriteHeader(400)
			return
		}
		f.controlReceipts = append(f.controlReceipts, receipt)
		if f.dropReceipt {
			f.dropReceipt = false
			dropResponse(w)
			return
		}
		json.NewEncoder(w).Encode(nodewire.ReceiptResponse{SchemaVersion: 1, NodeID: receipt.NodeID, OperationID: receipt.OperationID, Status: "recorded"})
	default:
		w.WriteHeader(404)
	}
}
func openAgent(t *testing.T, cfg Config) *Agent {
	t.Helper()
	a, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}
func checkCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != code {
		t.Fatalf("expected safe code %s; got %v", code, err)
	}
}

func TestEnrollmentLostReplyRestartAndMTLSHeartbeat(t *testing.T) {
	f := newFixture(t)
	f.dropEnroll = true
	a := openAgent(t, f.cfg)
	checkCode(t, a.Enroll(context.Background()), "node_connection_failed")
	if !f.persistedBeforeRequest {
		t.Fatal("identity not durable before request")
	}
	before, err := os.ReadFile(filepath.Join(f.cfg.StateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte(strings.Repeat("A", 43))) {
		t.Fatal("enrollment bearer persisted in state")
	}
	a.Close()
	a = openAgent(t, f.cfg)
	if err := a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.enrollment) != 2 || !reflect.DeepEqual(f.enrollment[0], f.enrollment[1]) {
		t.Fatal("lost enrollment response changed identity/request")
	}
	if err := os.Remove(f.cfg.TokenFile); err != nil {
		t.Fatal(err)
	}
	// Once enrolled the token is no longer required, including after restart.
	a.Close()
	a = openAgent(t, f.cfg)
	if err := a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.dropHeartbeat = true
	checkCode(t, a.Heartbeat(context.Background()), "node_connection_failed")
	if err := a.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.verifiedHeartbeat || len(f.heartbeats) != 2 || !reflect.DeepEqual(f.heartbeats[0], f.heartbeats[1]) {
		t.Fatal("mTLS or exact pending heartbeat retry failed")
	}
	firstBoot := f.heartbeats[0].BootID
	if f.heartbeats[0].Sequence != 1 || !reflect.DeepEqual(f.heartbeats[0].Capabilities, []string{"enrollment", "heartbeat", "certificate_renewal"}) {
		t.Fatal("invalid initial inventory")
	}
	if err := a.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.heartbeats[2].Sequence != 2 {
		t.Fatal("sequence did not advance after durable receipt")
	}
	a.Close()
	a = openAgent(t, f.cfg)
	if a.state.LastHeartbeat == nil || a.state.LastHeartbeat.Sequence != 2 {
		t.Fatal("receipt did not survive restart")
	}
	if err := a.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := f.heartbeats[3]
	if last.BootID == firstBoot || last.Sequence != 1 {
		t.Fatal("restart did not establish new boot identity")
	}
	for _, path := range []string{f.cfg.StateDir, filepath.Join(f.cfg.StateDir, "state.json"), filepath.Join(f.cfg.StateDir, "agent.lock")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatal("state permissions are not private")
		}
	}
}

func TestTrustRedirectAndResponseValidation(t *testing.T) {
	t.Run("foreign server CA", func(t *testing.T) {
		f := newFixture(t)
		mustWrite(t, f.cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw}))
		a := openAgent(t, f.cfg)
		checkCode(t, a.Enroll(context.Background()), "node_tls_verification_failed")
		if len(f.enrollment) != 0 {
			t.Fatal("token sent before authenticating server")
		}
	})
	t.Run("hostname verified", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.PanelURL = strings.Replace(f.cfg.PanelURL, "127.0.0.1", "localhost", 1)
		a := openAgent(t, f.cfg)
		checkCode(t, a.Enroll(context.Background()), "node_tls_verification_failed")
		if len(f.enrollment) != 0 {
			t.Fatal("token sent to mismatched hostname")
		}
	})
	t.Run("no redirects", func(t *testing.T) {
		f := newFixture(t)
		var mu sync.Mutex
		count := 0
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); count++; mu.Unlock() }))
		defer target.Close()
		f.redirect = target.URL
		a := openAgent(t, f.cfg)
		checkCode(t, a.Enroll(context.Background()), "node_redirect_rejected")
		mu.Lock()
		defer mu.Unlock()
		if count != 0 {
			t.Fatal("token forwarded on redirect")
		}
	})
	for _, field := range []string{"node", "serial", "expiry", "key"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			f.mutate = func(r *nodewire.EnrollmentResponse) {
				switch field {
				case "node":
					r.NodeID = "00000000-0000-4000-8000-000000000002"
				case "serial":
					r.Serial = "ff"
				case "expiry":
					r.ExpiresAt = r.ExpiresAt.Add(time.Second)
				case "key":
					_, key, _ := ed25519.GenerateKey(rand.Reader)
					csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
					replacement, _ := f.issue(nodewire.EnrollmentRequest{NodeID: testNode, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
					*r = replacement
				}
			}
			a := openAgent(t, f.cfg)
			checkCode(t, a.Enroll(context.Background()), "node_enrollment_response_mismatch")
			if a.state.Enrollment != nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestPrivateStorageAndStateFailClosed(t *testing.T) {
	t.Run("token modes", func(t *testing.T) {
		f := newFixture(t)
		os.Chmod(f.cfg.TokenFile, 0644)
		a := openAgent(t, f.cfg)
		checkCode(t, a.Enroll(context.Background()), "node_file_not_private")
	})
	t.Run("token symlink", func(t *testing.T) {
		f := newFixture(t)
		original := f.cfg.TokenFile
		f.cfg.TokenFile += ".link"
		os.Symlink(original, f.cfg.TokenFile)
		a := openAgent(t, f.cfg)
		checkCode(t, a.Enroll(context.Background()), "node_file_unreadable")
	})
	t.Run("token hardlink", func(t *testing.T) {
		f := newFixture(t)
		os.Link(f.cfg.TokenFile, f.cfg.TokenFile+".link")
		a := openAgent(t, f.cfg)
		checkCode(t, a.Enroll(context.Background()), "node_file_invalid")
	})
	t.Run("fifo nonblocking", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.TokenFile += ".fifo"
		if err := unix.Mkfifo(f.cfg.TokenFile, 0600); err != nil {
			t.Fatal(err)
		}
		a := openAgent(t, f.cfg)
		checkCode(t, a.Enroll(context.Background()), "node_file_invalid")
	})
	t.Run("directory modes", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Mkdir(f.cfg.StateDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f.cfg.StateDir, 0755); err != nil {
			t.Fatal(err)
		}
		_, err := Open(f.cfg)
		checkCode(t, err, "node_state_directory_not_private")
	})
	t.Run("directory symlink", func(t *testing.T) {
		f := newFixture(t)
		os.Symlink(t.TempDir(), f.cfg.StateDir)
		_, err := Open(f.cfg)
		checkCode(t, err, "node_state_directory_invalid")
	})
	t.Run("concurrent processes", func(t *testing.T) {
		f := newFixture(t)
		a := openAgent(t, f.cfg)
		_, err := Open(f.cfg)
		checkCode(t, err, "node_state_busy")
		a.Close()
		openAgent(t, f.cfg)
	})
	t.Run("state symlink before save", func(t *testing.T) {
		f := newFixture(t)
		a := openAgent(t, f.cfg)
		target := filepath.Join(t.TempDir(), "protected")
		mustWrite(t, target, []byte("unchanged"))
		os.Symlink(target, filepath.Join(f.cfg.StateDir, "state.json"))
		checkCode(t, a.Enroll(context.Background()), "node_state_unreadable")
		raw, _ := os.ReadFile(target)
		if string(raw) != "unchanged" || len(f.enrollment) != 0 {
			t.Fatal("unsafe write/network request")
		}
	})
	for _, kind := range []string{"corrupt", "trailing", "unknown", "future control", "configuration pin", "different token"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.dropEnroll = true
			a := openAgent(t, f.cfg)
			checkCode(t, a.Enroll(context.Background()), "node_connection_failed")
			state := a.state
			a.Close()
			path := filepath.Join(f.cfg.StateDir, "state.json")
			raw, _ := json.Marshal(state)
			want := "node_state_invalid"
			switch kind {
			case "corrupt":
				raw = []byte("{")
			case "trailing":
				raw = append(raw, []byte(" {}")...)
			case "unknown":
				raw = append(raw[:len(raw)-1], []byte(",\"unknown\":true}")...)
			case "future control":
				state.Control = &controlWatermark{AuthorityEpoch: 1}
				raw, _ = json.Marshal(state)
				want = "node_state_requires_newer_runtime"
			case "configuration pin":
				f.cfg.PanelURL += "0"
				want = "node_identity_configuration_changed"
			case "different token":
				token, _ := json.Marshal(enrollmentToken{NodeID: testNode, Token: strings.Repeat("B", 43)})
				mustWrite(t, f.cfg.TokenFile, token)
			}
			mustWrite(t, path, raw)
			if kind == "different token" {
				a = openAgent(t, f.cfg)
				checkCode(t, a.Enroll(context.Background()), "node_enrollment_identity_changed")
			} else {
				_, err := Open(f.cfg)
				checkCode(t, err, want)
			}
		})
	}
}

func TestRunRevocationAndBoundedSafeErrors(t *testing.T) {
	f := newFixture(t)
	a := openAgent(t, f.cfg)
	if err := a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.status = 403
	var codes []string
	checkCode(t, a.Run(context.Background(), func(code string) { codes = append(codes, code) }), "node_authorization_rejected")
	if !reflect.DeepEqual(codes, []string{"node_authorization_rejected"}) {
		t.Fatal("unsafe or missing revocation report")
	}
	f.status = 500
	ctx, cancel := context.WithCancel(context.Background())
	if err := a.Run(ctx, func(code string) {
		if code != "node_http_rejected" {
			t.Errorf("unexpected safe code: %s", code)
		}
		cancel()
	}); err != nil {
		t.Fatal(err)
	}
	for failures, want := range map[int]time.Duration{0: 1, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 30, 999: 30} {
		if retryDelay(failures) != want*time.Second {
			t.Fatal("unbounded retry delay")
		}
	}
}

func TestContextDeadlineAndExpiredCertificate(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		f := newFixture(t)
		started := make(chan struct{})
		release := make(chan struct{})
		f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release })
		defer close(release)
		a := openAgent(t, f.cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		checkCode(t, a.Enroll(ctx), "node_connection_failed")
		<-started
		if a.state.Enrollment != nil {
			t.Fatal("deadline accepted enrollment")
		}
	})
	t.Run("expired identity", func(t *testing.T) {
		f := newFixture(t)
		a := openAgent(t, f.cfg)
		if err := a.Enroll(context.Background()); err != nil {
			t.Fatal(err)
		}
		key, _ := parseKey(a.state.PrivateKeyPEM)
		leaf, _ := certificate(a.state.Enrollment.CertificatePEM)
		leaf.NotBefore = time.Now().Add(-2 * time.Hour)
		leaf.NotAfter = time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, key.Public(), f.key)
		if err != nil {
			t.Fatal(err)
		}
		a.state.Enrollment.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		a.state.Enrollment.ExpiresAt = leaf.NotAfter
		if err := writeState(a.dir, a.state); err != nil {
			t.Fatal(err)
		}
		checkCode(t, a.Heartbeat(context.Background()), "node_certificate_expired")
		a.Close()
		_, err = Open(f.cfg)
		checkCode(t, err, "node_certificate_expired")
		if len(f.heartbeats) != 0 {
			t.Fatal("expired certificate sent inventory")
		}
	})
}

func TestPEMRejectsMalformedPrefixAndTrailingMaterial(t *testing.T) {
	f := newFixture(t)
	a := openAgent(t, f.cfg)
	if err := a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		kind, value string
		parse       func(string) error
	}{
		{"PRIVATE KEY", a.state.PrivateKeyPEM, func(raw string) error { _, err := parseKey(raw); return err }},
		{"CERTIFICATE REQUEST", a.state.CSRPEM, func(raw string) error { _, err := parseCSR(raw); return err }},
		{"CERTIFICATE", a.state.Enrollment.CertificatePEM, func(raw string) error { _, err := certificate(raw); return err }},
	} {
		for _, raw := range []string{"garbage\n" + item.value, "-----BEGIN " + item.kind + "-----\ninvalid leading block\n" + item.value, item.value + "garbage", item.value + item.value} {
			if item.parse(raw) == nil {
				t.Fatalf("accepted malformed %s", item.kind)
			}
		}
	}
	ca, _ := os.ReadFile(f.cfg.CAFile)
	for _, raw := range [][]byte{append([]byte("garbage"), ca...), append([]byte("-----BEGIN CERTIFICATE-----\ninvalid leading block\n"), ca...), append(ca, []byte("garbage")...)} {
		if _, err := serverRoots(raw); err == nil {
			t.Fatal("accepted malformed server CA")
		}
	}
}
