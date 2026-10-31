package nodes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/jackc/pgx/v5"
	"math/big"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/connection"
	"testing"
	"time"
)

func TestManagedRollbackRestoresTLSClientTrust(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	var server Server
	var parent Node
	if err := f.tx(func(tx pgx.Tx) error {
		var e error
		server, _, e = f.s.CreateServerTx(ctx, tx, f.m(Node{}, "server"), "TLS rollback fixture")
		if e != nil {
			return e
		}
		parent, _, e = f.s.RegisterServerNodeTx(ctx, tx, f.m(Node{}, "register"), server.ID)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	fixture := func(serial int64) connection.Configuration {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "vpn.example.com"}, DNSNames: []string{"vpn.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		keyder, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return connection.Configuration{Public: connection.Spec{Template: connection.GRPC, Version: 1, Host: "vpn.example.com", ServerName: "vpn.example.com", ListenIP: "0.0.0.0", Port: 8443, ServiceName: "vpn"}, Private: connection.PrivateMaterial{CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyder}))}}
	}
	old, newer := fixture(1), fixture(2)
	var current ManagedConnection
	if err := f.tx(func(tx pgx.Tx) error {
		batch, _, e := f.s.CreateManagedConnectionsTx(ctx, tx, f.m(parent, "create"), []ManagedRequest{{Name: "gRPC", Configuration: old, TrustedCAPEM: old.Private.CertificatePEM, GroupID: access.DefaultGroupID, Enabled: true}})
		if e == nil {
			current = batch.Connections[0]
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.tx(func(tx pgx.Tx) error {
		next, _, e := f.s.UpdateManagedConnectionTx(ctx, tx, f.m(Node{ID: current.ID, Revision: current.VPN.NodeRevision}, "replace"), ManagedUpdate{ReplacePrivate: true, Request: ManagedRequest{Name: "gRPC", Configuration: newer, TrustedCAPEM: newer.Private.CertificatePEM, GroupID: access.DefaultGroupID, Enabled: false}})
		if e == nil {
			current = next
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.tx(func(tx pgx.Tx) error {
		next, _, e := f.s.UpdateManagedConnectionTx(ctx, tx, f.m(Node{ID: current.ID, Revision: current.VPN.NodeRevision}, "rollback"), ManagedUpdate{RollbackRevision: 1})
		if e == nil && (next.VPN.Enabled || next.VPN.Endpoint.TrustedCAPEM != old.Private.CertificatePEM) {
			t.Error("rollback lost historical client trust or restored access")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}
