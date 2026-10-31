package nodeagent

import (
	"context"
	"errors"
	"reflect"
	"salfetka/panel/internal/nodewire"
	"testing"
	"time"
)

func TestRenewalLostReplyRestartAndSameIdentity(t *testing.T) {
	f := newFixture(t)
	f.shortCertificate = true
	a, err := Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	original := a.state
	f.dropRenewal = true
	if err = a.Renew(context.Background()); err == nil {
		t.Fatal("lost renewal response not reported")
	}
	if a.state.Enrollment.Serial != original.Enrollment.Serial {
		t.Fatal("unsaved renewal used")
	}
	a.Close()
	a, err = Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.state.PrivateKeyPEM != original.PrivateKeyPEM || a.state.NodeID != original.NodeID || a.state.CSRPEM != original.CSRPEM || !reflect.DeepEqual(a.state.Control, original.Control) {
		t.Fatal("renewal replaced identity/control")
	}
	saved := *a.state.Enrollment
	a.Close()
	a, err = Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !reflect.DeepEqual(*a.state.Enrollment, saved) {
		t.Fatal("renewed certificate not durable")
	}
	if err = a.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = a.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.renewalCalls != 2 {
		t.Fatal("renewal outside window")
	}
}
func TestRenewalAmbiguousPersistStopsUntilReadback(t *testing.T) {
	f := newFixture(t)
	f.shortCertificate = true
	a, err := Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.persist = func(fd int, s localState) error {
		if err := writeState(fd, s); err != nil {
			return err
		}
		return errors.New("synthetic directory fsync failure")
	}
	if err = a.Renew(context.Background()); err == nil || err.Error() != "node_control_storage_failed" {
		t.Fatal(err)
	}
	if err = a.Heartbeat(context.Background()); err == nil {
		t.Fatal("continued after ambiguous write")
	}
	a.Close()
	a, err = Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.state.Enrollment.Serial != "3" {
		t.Fatal("committed renewal lost")
	}
	if err = a.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestRenewalRejectsWrongIssuerAndClockRollback(t *testing.T) {
	f := newFixture(t)
	f.shortCertificate = true
	a, err := Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err = a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mutate = func(r *nodewire.EnrollmentResponse) { r.NodeID = "00000000-0000-4000-8000-000000000002" }
	if err = a.Renew(context.Background()); err == nil {
		t.Fatal("foreign renewal accepted")
	}
	if a.state.Enrollment.Serial != "2" {
		t.Fatal("invalid response persisted")
	}
	a.now = func() time.Time { return time.Now().Add(-time.Hour) }
	if err = a.Renew(context.Background()); err == nil || err.Error() != "node_clock_untrusted" {
		t.Fatal("rollback allowed renewal", err)
	}
}

func TestManagedIdentityRejectsForeignOrUnenrolledState(t *testing.T) {
	f := newFixture(t)
	cfg := f.cfg
	cfg.ExpectedNodeID = testNode
	if a, err := Open(cfg); err == nil {
		a.Close()
		t.Fatal("managed mode bootstrapped unknown identity")
	}
	a, err := Open(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.Close()
	cfg.ExpectedNodeID = "00000000-0000-4000-8000-000000000002"
	if a, err := Open(cfg); err == nil {
		a.Close()
		t.Fatal("adopted foreign node state")
	}
	cfg.ExpectedNodeID = testNode
	a, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err = a.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
}
