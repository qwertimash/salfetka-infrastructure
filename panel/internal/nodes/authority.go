package nodes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

var ErrAuthority = errors.New("node_authority_unavailable")

type Authority struct {
	certificate    *x509.Certificate
	key            ed25519.PrivateKey
	certificatePEM []byte
}

func GenerateAuthority() ([]byte, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrAuthority
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Salfetka node authority"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, ErrAuthority
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrAuthority
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})...)
	return bundle, nil
}

// decodeFirst never lets pem.Decode skip a malformed leading block in favor
// of a later valid one. Only whitespace may separate the two bundle blocks.
func decodeFirst(raw []byte, kind string) (*pem.Block, []byte, error) {
	raw = bytes.TrimSpace(raw)
	begin := []byte("-----BEGIN " + kind + "-----")
	end := []byte("-----END " + kind + "-----")
	if !bytes.HasPrefix(raw, begin) {
		return nil, nil, ErrAuthority
	}
	i := bytes.Index(raw, end)
	if i < 0 {
		return nil, nil, ErrAuthority
	}
	stop := i + len(end)
	segment := raw[:stop]
	if bytes.Contains(segment[len(begin):], []byte("-----BEGIN ")) {
		return nil, nil, ErrAuthority
	}
	block, rest := pem.Decode(segment)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, ErrAuthority
	}
	return block, raw[stop:], nil
}
func LoadAuthority(bundle []byte) (*Authority, error) {
	if len(bundle) > 65536 {
		return nil, ErrAuthority
	}
	certificate, rest, err := decodeFirst(bundle, "CERTIFICATE")
	if err != nil {
		return nil, ErrAuthority
	}
	private, rest, err := decodeFirst(rest, "PRIVATE KEY")
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrAuthority
	}
	cert, err := x509.ParseCertificate(certificate.Bytes)
	if err != nil {
		return nil, ErrAuthority
	}
	parsed, err := x509.ParsePKCS8PrivateKey(private.Bytes)
	if err != nil {
		return nil, ErrAuthority
	}
	key, ok := parsed.(ed25519.PrivateKey)
	pub, pubOK := cert.PublicKey.(ed25519.PublicKey)
	now := time.Now()
	if !ok || !pubOK || !bytes.Equal(key.Public().(ed25519.PublicKey), pub) || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.CheckSignatureFrom(cert) != nil {
		return nil, ErrAuthority
	}
	return &Authority{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}, nil
}
func (a *Authority) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if a != nil && a.certificate != nil {
		pool.AddCert(a.certificate)
	}
	return pool
}
func (a *Authority) Bind(ctx context.Context, pool *pgxpool.Pool) error {
	if a == nil || a.certificate == nil || pool == nil {
		return ErrAuthority
	}
	hash := sha256.Sum256(a.certificate.Raw)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return ErrAuthority
	}
	defer database.Rollback(tx)
	if _, err = tx.Exec(ctx, "INSERT INTO nodes_authority_state(singleton,fingerprint) VALUES(true,$1) ON CONFLICT(singleton) DO NOTHING", hash[:]); err != nil {
		return ErrAuthority
	}
	var current []byte
	if err = tx.QueryRow(ctx, "SELECT fingerprint FROM nodes_authority_state WHERE singleton").Scan(&current); err != nil || !bytes.Equal(hash[:], current) {
		return ErrAuthority
	}
	if tx.Commit(ctx) != nil {
		return ErrAuthority
	}
	return nil
}
func randomSerial() (*big.Int, error) {
	v, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, ErrAuthority
	}
	if v.Sign() == 0 {
		v.SetInt64(1)
	}
	return v, nil
}
func parseCSR(raw string) (*x509.CertificateRequest, error) {
	if len(raw) > 8192 {
		return nil, ErrProof
	}
	block, rest, err := decodeFirst([]byte(raw), "CERTIFICATE REQUEST")
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrProof
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, ErrProof
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, ErrProof
	}
	return csr, nil
}
func (a *Authority) issue(nodeID string, csr *x509.CertificateRequest, now time.Time) (nodewire.EnrollmentResponse, error) {
	now = now.UTC().Truncate(time.Second)
	out := nodewire.EnrollmentResponse{}
	if a == nil || a.certificate == nil || !database.ValidID(nodeID) || now.Before(a.certificate.NotBefore) || !now.Add(time.Minute).Before(a.certificate.NotAfter) {
		return out, ErrAuthority
	}
	serial, err := randomSerial()
	if err != nil {
		return out, err
	}
	expiry := now.Add(24 * time.Hour)
	if expiry.After(a.certificate.NotAfter) {
		expiry = a.certificate.NotAfter
	}
	identity, _ := url.Parse(nodewire.IdentityURIPrefix + nodeID)
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: nodeID}, NotBefore: now.Add(-time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{identity}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.certificate, csr.PublicKey, a.key)
	if err != nil {
		return out, ErrAuthority
	}
	return nodewire.EnrollmentResponse{SchemaVersion: 1, NodeID: nodeID, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), AuthorityPEM: string(a.certificatePEM), Serial: serial.Text(16), ExpiresAt: expiry}, nil
}
