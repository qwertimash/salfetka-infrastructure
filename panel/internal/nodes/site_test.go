package nodes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/jackc/pgx/v5"
	"math/big"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"testing"
	"time"
)

func siteCertificate(t *testing.T, domain string, expiry time.Time) string {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func TestNodeSiteMetadataAuthorizationAndAutomaticConnections(t *testing.T) {
	f := controlFixture(t)
	ctx := context.Background()
	parent, cert := enrolled(t, f)
	_, other := enrolled(t, f)
	server, _ := database.NewID()
	if e := f.tx(func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "INSERT INTO infrastructure_servers(id,name,address,domain) VALUES($1,'Site fixture','192.0.2.1','node.example.com')", server); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "UPDATE nodes_registry SET server_id=$2 WHERE id=$1", parent.ID, server); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, "INSERT INTO server_nodes(server_id,node_id) VALUES($1,$2)", server, parent.ID)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.SiteInfo(ctx, other, parent.ID); e == nil {
		t.Fatal("other node read metadata")
	}
	info, e := f.s.SiteInfo(ctx, cert, parent.ID)
	if e != nil || info.Domain != "node.example.com" || info.Address != "192.0.2.1" {
		t.Fatal("metadata", e)
	}
	boot, _ := database.NewID()
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	r := nodewire.HeartbeatRequest{SchemaVersion: 1, NodeID: parent.ID, BootID: boot, Sequence: 1, Version: "0.7.0", Platform: "linux", Arch: "amd64", Capabilities: []string{"managed_connections_v1"}, Site: &nodewire.SiteStatus{Domain: "node.example.com", State: "ready", ExpiresAt: expiry, CertificatePEM: siteCertificate(t, "node.example.com", expiry)}}
	if _, _, e = f.s.Heartbeat(ctx, cert, r); e != nil {
		t.Fatal(e)
	}
	requests := []ManagedRequest{}
	for _, template := range connection.Templates() {
		spec := connection.Spec{CertificateSource: "node", Template: template.ID, Version: 1, Host: info.Address, ServerName: info.Domain, ListenIP: "0.0.0.0"}
		switch template.ID {
		case connection.Reality:
			spec.RealityTarget = "127.0.0.1:8445"
		case connection.GRPC:
			spec.ServiceName = "vpn"
		case connection.XHTTP:
			spec.Path = "/vpn"
		}
		requests = append(requests, ManagedRequest{Name: template.Name, GroupID: access.DefaultGroupID, Enabled: true, Configuration: connection.Configuration{Public: spec}})
	}
	if e = f.tx(func(tx pgx.Tx) error {
		_, _, e := f.s.CreateManagedConnectionsTx(ctx, tx, f.m(parent, "auto"), requests)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	signed, e := f.s.ConnectionsDesired(ctx, cert, parent.ID)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := nodecontrol.LoadPublicKey(f.s.Signer.PublicPEM())
	plan, e := nodecontrol.VerifyConnections(pub, signed)
	if e != nil || len(plan.Connections) != 4 {
		t.Fatal("signed plan", e)
	}
	for _, c := range plan.Connections {
		if c.Configuration.Private.CertificatePEM != "" || c.Configuration.Private.KeyPEM != "" || c.Configuration.Public.CertificateSource != "node" {
			t.Fatal("TLS private material sent by panel")
		}
	}
	r.Sequence++
	r.Site = &nodewire.SiteStatus{Domain: "foreign.example.com", State: "unavailable"}
	if _, _, e = f.s.Heartbeat(ctx, cert, r); e == nil {
		t.Fatal("foreign domain accepted")
	}
	r.Site = &nodewire.SiteStatus{Domain: info.Domain, State: "unavailable"}
	if _, _, e = f.s.Heartbeat(ctx, cert, r); e != nil {
		t.Fatal(e)
	}
	if e = f.tx(func(tx pgx.Tx) error {
		current, e := f.s.GetTx(ctx, tx, parent.ID)
		if e != nil {
			return e
		}
		_, _, e = f.s.CreateManagedConnectionsTx(ctx, tx, f.m(current, "not-ready"), requests[:1])
		return e
	}); e == nil {
		t.Fatal("unready node provisioned")
	}
}
func TestNodeSiteReportRejectsPrivateWrongAndExpiredCertificates(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	r := &nodewire.SiteStatus{Domain: "node.example.com", State: "ready", ExpiresAt: expiry, CertificatePEM: siteCertificate(t, "node.example.com", expiry)}
	if !validSite(r, time.Now()) {
		t.Fatal("valid public report rejected")
	}
	good := r.CertificatePEM
	for _, v := range []string{good + "-----BEGIN " + "PRIVATE KEY-----\nAA==\n-----END " + "PRIVATE KEY-----", siteCertificate(t, "foreign.example.com", time.Now().Add(time.Hour)), siteCertificate(t, "node.example.com", time.Now().Add(-time.Minute))} {
		r.CertificatePEM = v
		if validSite(r, time.Now()) {
			t.Fatal("unsafe site report")
		}
	}
}
