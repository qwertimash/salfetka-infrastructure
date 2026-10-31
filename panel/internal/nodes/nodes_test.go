package nodes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/secrets"
)

type fixture struct {
	t     *testing.T
	p     *pgxpool.Pool
	s     *Store
	actor string
	seq   int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p := dbtest.New(t)
	bundle, err := GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	a, err := LoadAuthority(bundle)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := secrets.New(bytes.Repeat([]byte{7}, 32))
	actor, _ := database.NewID()
	return &fixture{t: t, p: p, s: New(p, v, a), actor: actor}
}
func (f *fixture) m(n Node, route string) Mutation {
	f.seq++
	return Mutation{ActorID: f.actor, Route: route, TargetID: n.ID, Revision: n.Revision, Key: fmt.Sprintf("node-mutation-%08d", f.seq)}
}
func (f *fixture) tx(fn func(pgx.Tx) error) error {
	tx, err := f.p.Begin(context.Background())
	if err != nil {
		return err
	}
	defer database.Rollback(tx)
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}
func (f *fixture) create() Node {
	f.t.Helper()
	var n Node
	m := f.m(Node{}, "create")
	if err := f.tx(func(tx pgx.Tx) error {
		var err error
		n, _, err = f.s.CreateTx(context.Background(), tx, m, "Synthetic node")
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}
func (f *fixture) enrollment(n Node) (EnrollmentCreated, Mutation) {
	f.t.Helper()
	m := f.m(n, "enrollment")
	var e EnrollmentCreated
	if err := f.tx(func(tx pgx.Tx) error {
		var err error
		e, _, err = f.s.EnrollmentTx(context.Background(), tx, m)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return e, m
}
func (f *fixture) get(id string) Node {
	f.t.Helper()
	var n Node
	if err := f.tx(func(tx pgx.Tx) error { var err error; n, err = f.s.GetTx(context.Background(), tx, id); return err }); err != nil {
		f.t.Fatal(err)
	}
	return n
}
func csr(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored-attacker-name"}, DNSNames: []string{"ignored.example.invalid"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})), key
}
func request(t *testing.T, e EnrollmentCreated) nodewire.EnrollmentRequest {
	raw, _ := csr(t)
	id, _ := database.NewID()
	return nodewire.EnrollmentRequest{SchemaVersion: 1, NodeID: e.Node.ID, Token: e.Enrollment.Token, RequestID: id, CSRPEM: raw}
}
func leaf(t *testing.T, response nodewire.EnrollmentResponse) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(response.CertificatePEM))
	if block == nil {
		t.Fatal("missing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
func enrolled(t *testing.T, f *fixture) (Node, *x509.Certificate) {
	e, _ := f.enrollment(f.create())
	r := request(t, e)
	response, _, err := f.s.Enroll(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return f.get(e.Node.ID), leaf(t, response)
}
func heartbeat(id string) nodewire.HeartbeatRequest {
	boot, _ := database.NewID()
	return nodewire.HeartbeatRequest{SchemaVersion: 1, NodeID: id, BootID: boot, Sequence: 1, Version: "0.3.0-b3.1", Platform: "linux", Arch: "arm64", Capabilities: []string{"enrollment", "heartbeat"}}
}
func TestAuthorityStrictBundleBindingAndClientOnlyCSR(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.s.Authority.Bind(ctx, f.p); err != nil {
		t.Fatal(err)
	}
	bundle, err := GenerateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := LoadAuthority(bundle)
	if err = other.Bind(ctx, f.p); !errors.Is(err, ErrAuthority) {
		t.Fatal("wrong authority replaced installation", err)
	}
	_, privateBlock := pem.Decode(bundle)
	between := append([]byte{}, bundle[:len(bundle)-len(privateBlock)]...)
	between = append(between, []byte("garbage\n")...)
	between = append(between, privateBlock...)
	for _, b := range [][]byte{append([]byte("-----BEGIN CERTIFICATE-----\ninvalid leading block\n"), bundle...), append([]byte("garbage"), bundle...), append(bundle, []byte("garbage")...), between} {
		if _, err = LoadAuthority(b); !errors.Is(err, ErrAuthority) {
			t.Fatal("noncanonical authority accepted")
		}
	}
	e, _ := f.enrollment(f.create())
	r := request(t, e)
	response, _, err := f.s.Enroll(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	cert := leaf(t, response)
	if cert.Subject.CommonName != e.Node.ID || len(cert.URIs) != 1 || cert.URIs[0].String() != nodewire.IdentityURIPrefix+e.Node.ID || len(cert.DNSNames) != 0 || cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || !cert.NotAfter.Equal(response.ExpiresAt) {
		t.Fatal("CSR controlled leaf identity or expiry")
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: f.s.Authority.CertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("client cert permitted as server")
	}
	if err = f.s.authorizeLeaf(cert, e.Node.ID); err != nil {
		t.Fatal(err)
	}
	otherID, _ := database.NewID()
	if err = f.s.authorizeLeaf(cert, otherID); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("cross-node cert")
	}
}
func TestEnrollmentEncryptedAdminReplayOneUseTTLAndCrossKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	e, m := f.enrollment(f.create())
	var replayed EnrollmentCreated
	var replay bool
	if err := f.tx(func(tx pgx.Tx) error { var err error; replayed, replay, err = f.s.EnrollmentTx(ctx, tx, m); return err }); err != nil || !replay || replayed.Enrollment.Token != e.Enrollment.Token {
		t.Fatal("lost admin response rotated token", err)
	}
	var encrypted, hash []byte
	if err := f.p.QueryRow(ctx, "SELECT result_ciphertext FROM nodes_admin_mutations WHERE idempotency_key=$1", m.Key).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(e.Enrollment.Token)) {
		t.Fatal("token stored in plaintext")
	}
	if err := f.p.QueryRow(ctx, "SELECT token_hash FROM nodes_enrollments WHERE node_id=$1", e.Node.ID).Scan(&hash); err != nil || len(hash) != 32 {
		t.Fatal("token hash")
	}
	raw, _ := json.Marshal(f.get(e.Node.ID))
	if strings.Contains(string(raw), e.Enrollment.Token) {
		t.Fatal("token in safe metadata")
	}
	r := request(t, e)
	bad := r
	bad.CSRPEM = "garbage" + bad.CSRPEM
	if _, _, err := f.s.Enroll(ctx, bad); !errors.Is(err, ErrProof) {
		t.Fatal("bad CSR", err)
	}
	bad = r
	bad.NodeID = f.create().ID
	if _, _, err := f.s.Enroll(ctx, bad); !errors.Is(err, ErrEnrollment) {
		t.Fatal("cross-node token", err)
	}
	first, replay, err := f.s.Enroll(ctx, r)
	if err != nil || replay {
		t.Fatal(err)
	}
	again, replay, err := f.s.Enroll(ctx, r)
	if err != nil || !replay || again != first {
		t.Fatal("lost enrollment response changed certificate", err)
	}
	bad = r
	bad.RequestID, _ = database.NewID()
	if _, _, err = f.s.Enroll(ctx, bad); !errors.Is(err, ErrConflict) {
		t.Fatal("consumed token new request", err)
	}
	bad = r
	bad.CSRPEM, _ = csr(t)
	if _, _, err = f.s.Enroll(ctx, bad); !errors.Is(err, ErrConflict) {
		t.Fatal("cross-key replay", err)
	}
	if _, err = f.p.Exec(ctx, "UPDATE nodes_enrollments SET expires_at=clock_timestamp()-interval '1 second' WHERE node_id=$1", e.Node.ID); err != nil {
		t.Fatal(err)
	}
	recovered, wasReplay, err := f.s.Enroll(ctx, r)
	if err != nil || !wasReplay || recovered != first {
		t.Fatal("lost certificate response after token TTL", err)
	}
	unused, _ := f.enrollment(f.create())
	expiredRequest := request(t, unused)
	if _, err = f.p.Exec(ctx, "UPDATE nodes_enrollments SET expires_at=clock_timestamp()-interval '1 second' WHERE node_id=$1", unused.Node.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.s.Enroll(ctx, expiredRequest); !errors.Is(err, ErrExpired) {
		t.Fatal("expired unused token consumed", err)
	}
}
func TestConcurrentEnrollmentExactlyOneCertificateAndReplacementToken(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	e, _ := f.enrollment(f.create())
	old := request(t, e)
	replacement, _ := f.enrollment(e.Node)
	if _, _, err := f.s.Enroll(ctx, old); !errors.Is(err, ErrEnrollment) {
		t.Fatal("old token after replacement", err)
	}
	r := request(t, replacement)
	var wg sync.WaitGroup
	results := make(chan nodewire.EnrollmentResponse, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); response, _, err := f.s.Enroll(ctx, r); results <- response; errs <- err }()
	}
	wg.Wait()
	a, b := <-results, <-results
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("duplicate certificates")
	}
	var count int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='node.enrolled'").Scan(&count); err != nil || count != 1 {
		t.Fatal("enrollment audit duplicate", err)
	}
	n := f.get(r.NodeID)
	m := f.m(n, "revoke")
	if err := f.tx(func(tx pgx.Tx) error { _, _, err := f.s.RevokeTx(ctx, tx, m); return err }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Enroll(ctx, r); !errors.Is(err, ErrEnrollment) {
		t.Fatal("revoked cert reissued on retry", err)
	}
}
func TestHeartbeatReplayFreshnessBootRetirementAndRevocation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	r := heartbeat(n.ID)
	first, replay, err := f.s.Heartbeat(ctx, cert, r)
	if err != nil || replay {
		t.Fatal(err)
	}
	again, replay, err := f.s.Heartbeat(ctx, cert, r)
	if err != nil || !replay || again != first {
		t.Fatal("heartbeat replay", err)
	}
	got := f.get(n.ID)
	if got.ContactState != "fresh" || got.EngineState != "not_configured" || got.Inventory == nil || !got.LastSeenAt.Equal(first.ReceivedAt) {
		t.Fatal("contact inventory")
	}
	bad := r
	bad.Version = "changed"
	if _, _, err = f.s.Heartbeat(ctx, cert, bad); !errors.Is(err, ErrConflict) {
		t.Fatal("sequence payload conflict", err)
	}
	r.Sequence = 2
	if _, _, err = f.s.Heartbeat(ctx, cert, r); err != nil {
		t.Fatal(err)
	}
	r.Sequence = 1
	if _, _, err = f.s.Heartbeat(ctx, cert, r); !errors.Is(err, ErrConflict) {
		t.Fatal("old sequence", err)
	}
	next := heartbeat(n.ID)
	if _, _, err = f.s.Heartbeat(ctx, cert, next); err != nil {
		t.Fatal(err)
	}
	r.Sequence = 3
	if _, _, err = f.s.Heartbeat(ctx, cert, r); !errors.Is(err, ErrConflict) {
		t.Fatal("retired boot resurrected", err)
	}
	if _, err = f.p.Exec(ctx, "UPDATE nodes_registry SET last_seen_at=clock_timestamp()-interval '2 minutes' WHERE id=$1", n.ID); err != nil {
		t.Fatal(err)
	}
	if f.get(n.ID).ContactState != "stale" {
		t.Fatal("missing heartbeat called healthy")
	}
	if _, _, err = f.s.Heartbeat(ctx, cert, next); err != nil {
		t.Fatal(err)
	}
	if f.get(n.ID).ContactState != "stale" {
		t.Fatal("replay refreshed observation")
	}
	bad = next
	bad.Capabilities = []string{"vpn_grant"}
	if _, _, err = f.s.Heartbeat(ctx, cert, bad); !errors.Is(err, ErrInvalid) {
		t.Fatal("unverified capability claimed", err)
	}
	m := f.m(f.get(n.ID), "revoke")
	if err = f.tx(func(tx pgx.Tx) error { _, _, err := f.s.RevokeTx(ctx, tx, m); return err }); err != nil {
		t.Fatal(err)
	}
	next.Sequence++
	if _, _, err = f.s.Heartbeat(ctx, cert, next); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked mTLS accepted", err)
	}
}
func TestHeartbeatRejectsForeignIssuerSerialAndExpiredDBCertificate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	r := heartbeat(n.ID)
	if _, _, err := f.s.Heartbeat(ctx, nil, r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("missing TLS cert")
	}
	foreign := newFixture(t)
	_, other := enrolled(t, foreign)
	if _, _, err := f.s.Heartbeat(ctx, other, r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign certificate", err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE nodes_registry SET serial='wrong' WHERE id=$1", n.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Heartbeat(ctx, cert, r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("stale serial", err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE nodes_registry SET serial=$2,certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", n.ID, cert.SerialNumber.Text(16)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Heartbeat(ctx, cert, r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired stored cert", err)
	}
}

func TestRevocationCommitRejectsWaitingHeartbeat(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	n, cert := enrolled(t, f)
	r := heartbeat(n.ID)
	first, _, err := f.s.Heartbeat(ctx, cert, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Sequence++
	tx, err := f.p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Rollback(tx)
	m := f.m(n, "revoke")
	if _, _, err = f.s.RevokeTx(ctx, tx, m); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, e := f.s.Heartbeat(ctx, cert, r); done <- e }()
	select {
	case err := <-done:
		t.Fatal("heartbeat bypassed revocation transaction", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatal("post-revoke heartbeat accepted", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat did not finish")
	}
	if !f.get(n.ID).LastSeenAt.Equal(first.ReceivedAt) {
		t.Fatal("revoked node updated observation")
	}
}
func TestConcurrentDifferentEnrollmentKeysCannotReplaceWinner(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	e, _ := f.enrollment(f.create())
	a, b := request(t, e), request(t, e)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, r := range []nodewire.EnrollmentRequest{a, b} {
		wg.Add(1)
		go func(r nodewire.EnrollmentRequest) { defer wg.Done(); _, _, err := f.s.Enroll(ctx, r); errs <- err }(r)
	}
	wg.Wait()
	e1, e2 := <-errs, <-errs
	if !((e1 == nil && errors.Is(e2, ErrConflict)) || (e2 == nil && errors.Is(e1, ErrConflict))) {
		t.Fatal("cross-key enrollment race", e1, e2)
	}
	var count int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='node.enrolled'").Scan(&count); err != nil || count != 1 {
		t.Fatal("more than one key issued", err)
	}
}
