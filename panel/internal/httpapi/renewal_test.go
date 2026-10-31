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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/secrets"
	"testing"
	"time"
)

func TestRenewalRealTLSStrictRequestReplayAndRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	bundle, err := nodes.GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := nodes.LoadAuthority(bundle)
	if err != nil {
		t.Fatal(err)
	}
	caBlock, rest := pem.Decode(bundle)
	ca, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(rest)
	caKey, _ := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	vault, _ := secrets.New(bytes.Repeat([]byte{8}, 32))
	f.handler.(*api).nodes = nodes.New(f.pool, vault, authority)
	id, _ := database.NewID()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse(nodewire.IdentityURIPrefix + id)
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{uri}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(ctx, "INSERT INTO nodes_registry(id,name,state,serial,public_key,certificate_expires_at) VALUES($1,'Synthetic renewal node','active','9',$2,$3)", id, []byte(pub), expires); err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	request := nodewire.RenewalRequest{SchemaVersion: 1, NodeID: id, PreviousSerial: "9", CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	body, _ := json.Marshal(request)
	server := httptest.NewUnstartedServer(f.handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: authority.CertPool()}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	clientFor := func(cert []byte) *http.Client {
		pair, e := tls.X509KeyPair(cert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
		if e != nil {
			t.Fatal(e)
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}
	}
	old := clientFor(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	post := func(c *http.Client, path string, raw []byte, want int) []byte {
		t.Helper()
		r, e := c.Post(server.URL+path, "application/json", bytes.NewReader(raw))
		if e != nil {
			t.Fatal("TLS request failed")
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != want {
			t.Fatalf("status %d expected %d", r.StatusCode, want)
		}
		return b
	}
	owner := f.owner(t)
	status(t, call(f.handler, "POST", nodewire.RenewalPath, string(body), &owner, nil), 401)
	post(old, nodewire.RenewalPath+"?extra=1", body, 400)
	post(old, nodewire.RenewalPath, append(append([]byte{}, body[:len(body)-1]...), []byte(",\"extra\":1}")...), 400)
	post(old, nodewire.RenewalPath, []byte(`{"schema_version":1,"schema_version":1}`), 400)
	raw := post(old, nodewire.RenewalPath, body, 200)
	if !bytes.Equal(raw, post(old, nodewire.RenewalPath, body, 200)) {
		t.Fatal("lost response retry changed issuance")
	}
	var response nodewire.EnrollmentResponse
	if json.Unmarshal(raw, &response) != nil {
		t.Fatal("response")
	}
	current := clientFor([]byte(response.CertificatePEM))
	request.PreviousSerial = response.Serial
	next, _ := json.Marshal(request)
	post(current, nodewire.RenewalPath, next, 409)
	// Retained TLS connections must still consult current revocation state.
	if _, err = f.pool.Exec(ctx, "UPDATE nodes_registry SET state='revoked' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	post(old, nodewire.RenewalPath, body, 401)
	post(current, nodewire.RenewalPath, next, 401)
	if bytes.Contains(f.logs.Bytes(), []byte(request.CSRPEM)) || bytes.Contains(f.logs.Bytes(), private) {
		t.Fatal("credential leaked")
	}
}
