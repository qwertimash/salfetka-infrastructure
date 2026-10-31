package xrayengine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"salfetka/panel/internal/antifraudnode"
)

func controllerFixture(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	writeControllerTLS(t, dir)
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	python := os.Getenv("B0_PYTHON")
	if python == "" {
		python = "python3"
	}
	cmd := exec.Command(python, "-m", "tests.antifraud_tls_fixture", dir)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = out.Close() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	var line string
	select {
	case line = <-ready:
	case <-time.After(15 * time.Second):
		t.Fatal("isolated controller startup timed out")
	}
	var result struct {
		Origin string `json:"origin"`
	}
	if json.Unmarshal([]byte(line), &result) != nil || !strings.HasPrefix(result.Origin, "https://127.0.0.1:") {
		// Wait for exec's stderr copier before reading its buffer on startup failure.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("isolated controller did not start", stderr.String())
	}
	cert, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(cert) {
		t.Fatal("fixture CA")
	}
	return result.Origin, dir, ca
}
func nodeBudget(t *testing.T, origin, dir, node string, ca *x509.CertPool, bindings map[string]string) *antifraudnode.Client {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, node+".pem"), filepath.Join(dir, node+".key"))
	if err != nil {
		t.Fatal(err)
	}
	session := strings.Repeat("d", 48)
	if node == "pl" {
		session = strings.Repeat("e", 48)
	}
	c, err := antifraudnode.New(origin, &tls.Config{RootCAs: ca, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, session, bindings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if err = c.OpenSession(context.Background(), ""); err != nil {
		t.Fatal("session", err)
	}
	// Repeat the exact startup request, as after losing its response.
	if err = c.OpenSession(context.Background(), ""); err != nil {
		t.Fatal("session retry", err)
	}
	return c
}
func TestAntifraudRealControllerTwoNodesTLSAndRelease(t *testing.T) {
	origin, dir, ca := controllerFixture(t)
	secondDevice := identity{"second-device@antifraud.invalid", "33333333-3333-4333-8333-333333333333"}
	de := nodeBudget(t, origin, dir, "de", ca, map[string]string{users[0].Secret: "a", users[1].Secret: "b", secondDevice.Secret: "a"})
	pl := nodeBudget(t, origin, dir, "pl", ca, map[string]string{users[0].Secret: "a"})
	runtimes := make([]*Runtime, 2)
	clients := make([]*engine, 2)
	kinds := []string{"vless_tls", "hy2_xray"}
	budgets := []*antifraudnode.Client{de, pl}
	tcp, _ := echoes(t)
	var b *flow
	var secondClient func() *engine
	for i, kind := range kinds {
		certs := syntheticCert(t)
		port := freePort(t, i == 1)
		backend := ""
		if i == 1 {
			backend = "hysteria2"
		}
		r, err := New(Config{Backend: backend, ListenIP: "127.0.0.1", Port: port, CertificatePEM: strings.Join(certs.leaf, "\n"), KeyPEM: strings.Join(certs.key, "\n"), LabLoopbackOnly: true, TrafficGate: budgets[i].Wait})
		if err != nil {
			t.Fatal(err)
		}
		runtimes[i] = r
		t.Cleanup(func() { r.Close() })
		apply(t, r, Grant{ID: users[0].Secret, Credential: users[0].Secret, Generation: 1, Enabled: true, ExpiresAt: time.Now().Add(time.Minute)})
		if i == 0 {
			apply(t, r, Grant{ID: users[1].Secret, Credential: users[1].Secret, Generation: 1, Enabled: true, ExpiresAt: time.Now().Add(time.Minute)})
			apply(t, r, Grant{ID: secondDevice.Secret, Credential: secondDevice.Secret, Generation: 1, Enabled: true, ExpiresAt: time.Now().Add(time.Minute)})
			secondClient = func() *engine { return startClient(t, kind, port, certs, secondDevice) }
		}
		if err = budgets[i].Sync(context.Background()); err != nil {
			t.Fatal("policy receipt", err)
		}
		clients[i] = startClient(t, kind, port, certs, users[0])
		if i == 0 {
			b = openFlow(t, startClient(t, kind, port, certs, users[1]), "tcp", tcp)
		}
	}
	flows := []*flow{openFlow(t, clients[0], "tcp", tcp), openFlow(t, clients[1], "tcp", tcp)}
	for _, f := range flows {
		if !f.exchange([]byte("warm")) {
			t.Fatal("initial stream")
		}
	}
	payload := bytes.Repeat([]byte("a"), 32*1024)
	done := make(chan bool, 2)
	started := time.Now()
	for _, f := range flows {
		go func(f *flow) { done <- f.exchange(payload) }(f)
	}
	bstarted := time.Now()
	if !b.exchange(bytes.Repeat([]byte("b"), 8192)) {
		t.Fatal("B failed")
	}
	bt := time.Since(bstarted)
	for range flows {
		if !<-done {
			t.Fatal("A traffic failed")
		}
	}
	elapsed := time.Since(started)
	if elapsed < time.Second || elapsed > 2600*time.Millisecond || bt > 500*time.Millisecond {
		t.Fatal("aggregate rate or B isolation", elapsed, bt)
	}
	// Disconnect A completely on this node, then return under a DIFFERENT
	// authenticated device/grant. A's other node keeps running throughout.
	flows[0].close()
	flows[0] = openFlow(t, secondClient(), "tcp", tcp)
	reentered := time.Now()
	for _, f := range flows {
		go func(f *flow) { done <- f.exchange(payload) }(f)
	}
	bReentered := time.Now()
	if !b.exchange(bytes.Repeat([]byte("b"), 8192)) {
		t.Fatal("B failed during A reconnect")
	}
	bReconnectElapsed := time.Since(bReentered)
	for range flows {
		if !<-done {
			t.Fatal("A reconnected flow failed")
		}
	}
	reconnectElapsed := time.Since(reentered)
	if reconnectElapsed < time.Second || reconnectElapsed > 2600*time.Millisecond || bReconnectElapsed > 500*time.Millisecond {
		t.Fatal("reconnect reset the account cap or queued B", reconnectElapsed, bReconnectElapsed)
	}
	// Real controller HTTP action, verified CA, no trust bypass and no redirects.
	httpClient := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer httpClient.CloseIdleConnections()
	req, _ := http.NewRequest("POST", origin+"/admin/release", strings.NewReader(`{"account_id":"a","incident_id":1,"actor":"local-owner"}`))
	req.Header.Set("Authorization", "Bearer local-fixture-admin-"+strings.Repeat("a", 48))
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("release", res.StatusCode)
	}
	for _, c := range budgets {
		if err = c.Sync(context.Background()); err != nil {
			t.Fatal("release receipt", err)
		}
	}
	started = time.Now()
	for _, f := range flows {
		if !f.exchange(payload) {
			t.Fatal("released flow")
		}
	}
	if time.Since(started) > 500*time.Millisecond || !b.exchange([]byte("B-after")) {
		t.Fatal("release did not restore existing streams")
	}
	for _, r := range runtimes {
		u, err := r.Usage(users[0].Secret)
		if err != nil || u.Uplink == nil || u.Downlink == nil || *u.Downlink < int64(len(payload)) {
			t.Fatal("real traffic counters missing")
		}
	}
	u, err := runtimes[0].Usage(secondDevice.Secret)
	if err != nil || u.Downlink == nil || *u.Downlink < int64(len(payload)*2) {
		t.Fatal("new authenticated device did not carry the test traffic")
	}
	t.Logf("controller+mTLS+VLESS+Hy2: A 128KiB %s; after device reconnect %s; B %s/%s; release passed", elapsed, reconnectElapsed, bt, bReconnectElapsed)
}

// Ephemeral CA and three role-separated certificates; all generation uses the
// standard library. No external CA, key store or production certificate access.
func writeControllerTLS(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-antifraud-test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, kind string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.pem", "CERTIFICATE", der)
	for i, id := range []string{"server", "de", "pl"} {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: id}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if id == "server" {
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			uri, _ := url.Parse("urn:salfetka:antifraud:node:" + id)
			cert.URIs = []*url.URL{uri}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err = x509.CreateCertificate(rand.Reader, cert, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		write(id+".pem", "CERTIFICATE", der)
		write(id+".key", "PRIVATE KEY", raw)
	}
}
