package nodes

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/jackc/pgx/v5"
	"reflect"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
	"sync"
	"testing"
	"time"
)

func renewalFixture(t *testing.T, f *fixture) (Node, *x509.Certificate, nodewire.RenewalRequest) {
	t.Helper()
	ctx := context.Background()
	e, _ := f.enrollment(f.create())
	r := request(t, e)
	if _, _, err := f.s.Enroll(ctx, r); err != nil {
		t.Fatal(err)
	}
	csr, _ := parseCSR(r.CSRPEM)
	before := f.s.Authority.certificate.NotBefore
	f.s.Authority.certificate.NotBefore = time.Now().Add(-48 * time.Hour)
	response, err := f.s.Authority.issue(r.NodeID, csr, time.Now().Add(-17*time.Hour))
	f.s.Authority.certificate.NotBefore = before
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Exec(ctx, "UPDATE nodes_registry SET serial=$2,certificate_expires_at=$3 WHERE id=$1", r.NodeID, response.Serial, response.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	return f.get(r.NodeID), leaf(t, response), nodewire.RenewalRequest{SchemaVersion: 1, NodeID: r.NodeID, PreviousSerial: response.Serial, CSRPEM: r.CSRPEM}
}
func TestRenewalConcurrentReplayBoundedOverlapAndRevoke(t *testing.T) {
	f := newFixture(t)
	n, old, request := renewalFixture(t, f)
	ctx := context.Background()
	type result struct {
		response nodewire.EnrollmentResponse
		replay   bool
		err      error
	}
	results := make(chan result, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, replay, err := f.s.Renew(ctx, old, request)
			results <- result{r, replay, err}
		}()
	}
	wg.Wait()
	close(results)
	var issued nodewire.EnrollmentResponse
	created := 0
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if issued.Serial == "" {
			issued = r.response
		}
		if !reflect.DeepEqual(issued, r.response) {
			t.Fatal("renewal replay changed response/deadline")
		}
		if !r.replay {
			created++
		}
	}
	if created != 1 {
		t.Fatal("multiple issuance effects")
	}
	current := f.get(n.ID)
	if current.Revision != n.Revision+1 || *current.Serial != issued.Serial {
		t.Fatal("registry renewal not atomic")
	}
	for _, cert := range []*x509.Certificate{old, leaf(t, issued)} {
		if _, err := f.s.Desired(ctx, cert, n.ID); err != nil {
			t.Fatal("valid certificate denied", err)
		}
		boot, _ := database.NewID()
		if _, _, err := f.s.Heartbeat(ctx, cert, nodewire.HeartbeatRequest{SchemaVersion: 1, NodeID: n.ID, BootID: boot, Sequence: 1, Version: "test", Platform: "linux", Arch: "arm64", Capabilities: []string{"heartbeat"}}); err != nil {
			t.Fatal(err)
		}
	}
	request.CSRPEM += "\n"
	if _, _, err := f.s.Renew(ctx, old, request); !errors.Is(err, ErrConflict) {
		t.Fatal("changed retry accepted", err)
	}
	if err := f.tx(func(tx pgx.Tx) error {
		allowed, err := f.s.serialAuthorized(ctx, tx, n.ID, old, current.Serial, current.CertificateExpiresAt, old.NotAfter)
		if allowed {
			t.Fatal("renewal extended old certificate expiry")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "DELETE FROM nodes_certificate_renewals WHERE node_id=$1", n.ID); err == nil {
		t.Fatal("immutable issuance deleted")
	}
	if err := f.tx(func(tx pgx.Tx) error { _, _, err := f.s.RevokeTx(ctx, tx, f.m(current, "revoke")); return err }); err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*x509.Certificate{old, leaf(t, issued)} {
		if _, err := f.s.Desired(ctx, cert, n.ID); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("revoked overlap certificate authorized", err)
		}
	}
}
func TestRenewalForeignKeyEarlyExpiryAndAuditRollback(t *testing.T) {
	f := newFixture(t)
	n, cert, r := renewalFixture(t, f)
	ctx := context.Background()
	other, _ := csr(t)
	bad := r
	bad.CSRPEM = other
	if _, _, err := f.s.Renew(ctx, cert, bad); !errors.Is(err, ErrProof) {
		t.Fatal("foreign key accepted", err)
	}
	otherNode, _ := database.NewID()
	bad = r
	bad.NodeID = otherNode
	if _, _, err := f.s.Renew(ctx, cert, bad); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign node accepted", err)
	}
	if _, err := f.p.Exec(ctx, "ALTER TABLE audit_events ADD CONSTRAINT renewal_failure CHECK(action <> 'node.certificate_renewed') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Renew(ctx, cert, r); err == nil {
		t.Fatal("audit failure ignored")
	}
	if current := f.get(n.ID); current.Revision != n.Revision || *current.Serial != *n.Serial {
		t.Fatal("partial renewal committed")
	}
	var count int
	f.p.QueryRow(ctx, "SELECT count(*) FROM nodes_certificate_renewals").Scan(&count)
	if count != 0 {
		t.Fatal("orphan renewal")
	}
	f.p.Exec(ctx, "ALTER TABLE audit_events DROP CONSTRAINT renewal_failure")
	issued, _, err := f.s.Renew(ctx, cert, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PreviousSerial = issued.Serial
	if _, _, err = f.s.Renew(ctx, leaf(t, issued), r); !errors.Is(err, ErrConflict) {
		t.Fatal("early issuance allowed", err)
	}
	expired := *cert
	expired.NotAfter = time.Now().Add(-time.Second)
	r.PreviousSerial = cert.SerialNumber.Text(16)
	if _, _, err = f.s.Renew(ctx, &expired, r); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired identity recovered implicitly", err)
	}
}
