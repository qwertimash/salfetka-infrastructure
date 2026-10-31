package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testDeliveryPair(t *testing.T, serial int64) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}

func TestDeliveryCertificateRotationKeepsLastValidPair(t *testing.T) {
	dir := t.TempDir()
	cert1, key1 := testDeliveryPair(t, 1)
	cert2, key2 := testDeliveryPair(t, 2)
	pair, err := tls.X509KeyPair(cert1, key1)
	if err != nil {
		t.Fatal(err)
	}
	c := &deliveryCertificate{certFile: filepath.Join(dir, "cert"), keyFile: filepath.Join(dir, "key"), pair: &pair}
	write := func(cert, key []byte) {
		t.Helper()
		if err := os.WriteFile(c.certFile, cert, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.keyFile, key, 0600); err != nil {
			t.Fatal(err)
		}
		c.nextRead = time.Time{}
	}
	serial := func(want int64) {
		t.Helper()
		got, err := c.get(nil)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(got.Certificate[0])
		if err != nil || leaf.SerialNumber.Int64() != want {
			t.Fatalf("certificate rotation: want serial %d", want)
		}
	}
	write(cert1, key1)
	serial(1)
	write(cert2, key1)
	serial(1) // Incomplete deployment must not break handshakes.
	write(cert2, key2)
	serial(2)
	if err := os.Chmod(c.keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	c.nextRead = time.Time{}
	serial(2) // Reject insecure replacement; retain valid pair.
	if err := os.Remove(c.certFile); err != nil {
		t.Fatal(err)
	}
	c.nextRead = time.Time{}
	serial(2)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() { defer group.Done(); _, _ = c.get(nil) }()
	}
	group.Wait()
}
