package nodesite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func bundle(t *testing.T, dir string, serial int64, expiry time.Time) *x509.CertPool {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "node.example.test"}, DNSNames: []string{"node.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	raw := append(cert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})...)
	temp := filepath.Join(dir, "new.pem")
	if err = os.WriteFile(temp, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(temp, filepath.Join(dir, "bundle.pem")); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	return roots
}
func TestTLSRotationAndHostVerification(t *testing.T) {
	dir := t.TempDir()
	roots := bundle(t, dir, 1, time.Now().Add(time.Hour))
	server := httptest.NewUnstartedServer(Handler("node.example.test", dir))
	server.TLS = TLS(dir, "node.example.test")
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	connect := func(roots *x509.CertPool, name string) (*tls.Conn, error) {
		return tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	}
	c, err := connect(roots, "node.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnectionState().NegotiatedProtocol != "h2" || c.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 1 {
		t.Fatal("wrong TLS")
	}
	c.Close()
	roots = bundle(t, dir, 2, time.Now().Add(time.Hour))
	c, err = connect(roots, "node.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 2 {
		t.Fatal("renewal not live")
	}
	c.Close()
	if c, e := connect(roots, "other.example.test"); e == nil {
		c.Close()
		t.Fatal("wrong SNI accepted")
	}
	bundle(t, dir, 3, time.Now().Add(-time.Minute))
	if c, e := connect(roots, "node.example.test"); e == nil {
		c.Close()
		t.Fatal("expired cert accepted")
	}
}
func TestWebsiteAndChallengeIsolation(t *testing.T) {
	dir := t.TempDir()
	challenge := filepath.Join(dir, ".well-known/acme-challenge")
	os.MkdirAll(challenge, 0755)
	os.WriteFile(filepath.Join(challenge, "token"), []byte("proof"), 0644)
	outside := filepath.Join(t.TempDir(), "private")
	os.WriteFile(outside, []byte("SECRET"), 0600)
	os.Symlink(outside, filepath.Join(challenge, "link"))
	h := Handler("node.example.test", dir)
	for _, tc := range []struct {
		path, host string
		code       int
		body       string
	}{{"/", "node.example.test", 200, "Field notes"}, {"/", "evil.test", 404, "Not found"}, {"/.well-known/acme-challenge/token", "node.example.test", 200, "proof"}, {"/.well-known/acme-challenge/link", "node.example.test", 404, "404"}, {"/.well-known/acme-challenge/../private", "node.example.test", 404, "404"}, {"/bundle.pem", "node.example.test", 404, "404"}, {"/.well-known/acme-challenge/token?x=1", "node.example.test", 404, "404"}} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.body) || strings.Contains(w.Body.String(), "SECRET") {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}
func TestBundleRejectsUnsafeOrMismatchedMaterial(t *testing.T) {
	dir := t.TempDir()
	bundle(t, dir, 1, time.Now().Add(time.Hour))
	if _, e := Load(dir, "other.example.test", time.Now()); e == nil {
		t.Fatal("SAN accepted")
	}
	cert, e := Load(dir, "node.example.test", time.Now())
	if e != nil || strings.Contains(cert.PEM, "PRIVATE") {
		t.Fatal("public report invalid")
	}
	path := filepath.Join(dir, "bundle.pem")
	os.Chmod(path, 0666)
	if _, e = Load(dir, "node.example.test", time.Now()); e == nil {
		t.Fatal("writable bundle accepted")
	}
	os.Chmod(path, 0600)
	os.Rename(path, filepath.Join(dir, "actual"))
	os.Symlink("actual", path)
	if _, e = Load(dir, "node.example.test", time.Now()); e == nil {
		t.Fatal("symlink accepted")
	}
}
