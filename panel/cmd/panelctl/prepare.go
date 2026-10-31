package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
)

// prepare only creates fresh local installation files. The self-signed TLS
// certificate is for localhost B1 evaluation, never a public certificate claim.
func prepare(args []string) error {
	fs := flag.NewFlagSet("prepare", flag.ContinueOnError)
	dir := fs.String("dir", "private/compose", "new empty directory for installation secrets")
	if e := fs.Parse(args); e != nil || fs.NArg() != 0 {
		return errors.New("invalid_arguments")
	}
	if e := os.MkdirAll(*dir, 0700); e != nil {
		return errors.New("prepare_directory_failed")
	}
	info, e := os.Lstat(*dir)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("prepare_directory_not_private")
	}
	entries, e := os.ReadDir(*dir)
	if e != nil || len(entries) != 0 {
		return errors.New("prepare_directory_must_be_empty")
	}
	random := func() (string, error) {
		b := make([]byte, 32)
		_, e := rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b), e
	}
	dbPassword, e := random()
	if e != nil {
		return errors.New("random_source_failed")
	}
	runtimePassword, e := random()
	if e != nil {
		return errors.New("random_source_failed")
	}
	masterKey, e := random()
	if e != nil {
		return errors.New("random_source_failed")
	}
	issuer, e := nodes.GenerateAuthority()
	if e != nil {
		return errors.New("node_authority_generation_failed")
	}
	signingKey, e := nodecontrol.GenerateSigner()
	if e != nil {
		return errors.New("node_signer_generation_failed")
	}
	signer, e := nodecontrol.LoadSigner(signingKey)
	if e != nil {
		return errors.New("node_signer_generation_failed")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return errors.New("tls_generation_failed")
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return errors.New("random_source_failed")
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Salfetka B1 localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	cert, e := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if e != nil {
		return errors.New("tls_generation_failed")
	}
	keyBytes, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return errors.New("tls_generation_failed")
	}
	files := map[string][]byte{
		"node-signer":       signingKey,
		"node-signer.pub":   signer.PublicPEM(),
		"node-authority":    issuer,
		"master-key":        []byte(masterKey + "\n"),
		"postgres-password": []byte(dbPassword + "\n"), "runtime-password": []byte(runtimePassword + "\n"),
		"database-migrator-url": []byte("postgres://panel_migrator:" + dbPassword + "@postgres:5432/panel?sslmode=disable\n"),
		"database-runtime-url":  []byte("postgres://panel_runtime:" + runtimePassword + "@postgres:5432/panel?sslmode=disable\n"),
		"tls.crt":               pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
		"tls.key":               pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}),
		"compose.env":           []byte("PANEL_UID=" + strconv.Itoa(os.Getuid()) + "\nPANEL_GID=" + strconv.Itoa(os.Getgid()) + "\n"),
	}
	for name, data := range files {
		f, e := os.OpenFile(filepath.Join(*dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("prepare_file_create_failed")
		}
		_, e = f.Write(data)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return errors.New("prepare_file_write_failed")
		}
	}
	fmt.Println("local_installation_files_created_no_secrets_printed")
	return nil
}
