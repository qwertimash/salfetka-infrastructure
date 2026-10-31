package xrayengine

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func managed(t *testing.T) (*Runtime, certs, int) {
	return managedKind(t, "vless_tls")
}

func TestSmallClockCorrectionPreservesFlowsAndOriginalExpiry(t *testing.T) {
	for _, kind := range []string{"vless_tls", "hy2_xray"} {
		t.Run(kind, func(t *testing.T) {
			r, ca, port := managedKind(t, kind)
			tcp, udp := echoes(t)
			g := Grant{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: time.Now().Add(2 * time.Second)}
			apply(t, r, g)
			a := startClient(t, kind, port, ca, users[0])
			ft, fu := openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
			check(t, ft.exchange([]byte("before")) && fu.exchange([]byte("before")), "initial flow failed")
			r.mu.Lock()
			r.now = func() time.Time { return time.Now().UTC().Add(-300 * time.Millisecond) }
			r.mu.Unlock()
			g.Generation++
			apply(t, r, g)
			check(t, ft.exchange([]byte("after")) && fu.exchange([]byte("after")), "small correction interrupted existing flow")
			time.Sleep(time.Until(g.ExpiresAt) + 100*time.Millisecond)
			u, err := r.Usage(g.ID)
			check(t, err == nil && !u.Active, "clock correction extended expiry")
			check(t, !ft.exchange([]byte("expired")) && !fu.exchange([]byte("expired")), "expired flow still usable")
			check(t, errors.Is(r.Apply(g), ErrExpired), "expired generation replayed")
		})
	}
}
func managedKind(t *testing.T, kind string) (*Runtime, certs, int) {
	t.Helper()
	backend := ""
	if kind == "hy2_xray" {
		backend = "hysteria2"
	}
	ca := syntheticCert(t)
	port := freePort(t, kind == "hy2_xray")
	r, err := New(Config{Backend: backend, ListenIP: "127.0.0.1", Port: port, CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n"), LabLoopbackOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r, ca, port
}
func apply(t *testing.T, r *Runtime, g Grant) {
	t.Helper()
	if err := r.Apply(g); err != nil {
		t.Fatal(err)
	}
}
func waitInactive(t *testing.T, r *Runtime, id string) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		u, e := r.Usage(id)
		if e == nil && !u.Active {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("lease not enforced")
}

func TestRuntimeLeaseRenewReplayAndIndependentExpiry(t *testing.T) {
	runtimeLeaseRenewReplayAndIndependentExpiry(t, "vless_tls")
}
func TestHysteriaRuntimeLeaseRenewReplayAndIndependentExpiry(t *testing.T) {
	runtimeLeaseRenewReplayAndIndependentExpiry(t, "hy2_xray")
}
func runtimeLeaseRenewReplayAndIndependentExpiry(t *testing.T, kind string) {
	r, ca, port := managedKind(t, kind)
	tcp, udp := echoes(t)
	ga := Grant{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: time.Now().Add(time.Second)}
	gb := Grant{ID: users[1].Secret, Generation: 1, Enabled: true, Credential: users[1].Secret, ExpiresAt: time.Now().Add(10 * time.Second)}
	apply(t, r, ga)
	apply(t, r, gb)
	empty, _ := r.Usage(ga.ID)
	if empty.Uplink != nil || empty.Downlink != nil {
		t.Fatal("missing counters fabricated as zero")
	}
	a, b := startClient(t, kind, port, ca, users[0]), startClient(t, kind, port, ca, users[1])
	at, au := openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
	bt, bu := openFlow(t, b, "tcp", tcp), openFlow(t, b, "udp", udp)
	check(t, at.exchange([]byte("a-live")) && au.exchange([]byte("a-udp")) && bt.exchange([]byte("b-live")) && bu.exchange([]byte("b-udp")), "runtime traffic failed")
	forged := ga
	forged.ExpiresAt = ga.ExpiresAt.Add(time.Second)
	if !errors.Is(r.Apply(forged), ErrConflict) {
		t.Fatal("same generation changed lease")
	}
	renewed := forged
	renewed.Generation = 2
	apply(t, r, renewed)
	apply(t, r, renewed)
	// Old deadline expires; newer lease preserves existing TCP and UDP.
	time.Sleep(time.Until(ga.ExpiresAt) + 100*time.Millisecond)
	check(t, at.exchange([]byte("a-renewed")) && au.exchange([]byte("a-renewed-udp")), "renew disconnected live sessions")
	waitInactive(t, r, ga.ID)
	check(t, !at.exchange([]byte("a-expired")) && !au.exchange([]byte("a-expired-udp")), "expired active flows survived")
	check(t, at.outcome != "timeout" && au.outcome != "timeout", "expiry did not terminate")
	check(t, !one(t, a, "tcp", tcp) && !one(t, a, "udp", udp), "expired saved config accepted")
	check(t, bt.exchange([]byte("b-survives")) && bu.exchange([]byte("b-survives-udp")), "expiry affected B")
	if !errors.Is(r.Apply(renewed), ErrExpired) {
		t.Fatal("exact replay resurrected expired lease")
	}
	before, _ := r.Usage(gb.ID)
	after, _ := r.Usage(gb.ID)
	check(t, before.InstanceEpoch != "" && before.InstanceEpoch == after.InstanceEpoch && before.Uplink != nil && after.Uplink != nil && *before.Uplink == *after.Uplink, "usage read reset counters")
	apply(t, r, Grant{ID: gb.ID, Generation: 2})
	check(t, !bt.exchange([]byte("b-revoked")) && !bu.exchange([]byte("b-revoked-udp")), "explicit runtime revoke")
	if !errors.Is(r.Apply(gb), ErrConflict) {
		t.Fatal("stale readd accepted")
	}
}

func TestRuntimeClockRollbackTerminatesAndStaysDenied(t *testing.T) {
	runtimeClockRollbackTerminatesAndStaysDenied(t, "vless_tls")
}
func TestHysteriaRuntimeClockRollbackTerminatesAndStaysDenied(t *testing.T) {
	runtimeClockRollbackTerminatesAndStaysDenied(t, "hy2_xray")
}
func runtimeClockRollbackTerminatesAndStaysDenied(t *testing.T, kind string) {
	r, ca, port := managedKind(t, kind)
	tcp, _ := echoes(t)
	g := Grant{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: time.Now().Add(time.Minute)}
	apply(t, r, g)
	a := startClient(t, kind, port, ca, users[0])
	f := openFlow(t, a, "tcp", tcp)
	check(t, f.exchange([]byte("before-clock")), "setup")
	r.mu.Lock()
	r.now = func() time.Time { return time.Now().Add(-time.Hour) }
	r.mu.Unlock()
	waitInactive(t, r, g.ID)
	check(t, !f.exchange([]byte("after-clock")) && f.outcome != "timeout", "clock rollback retained flow")
	r.mu.Lock()
	r.now = time.Now
	r.mu.Unlock()
	g.Generation++
	if !errors.Is(r.Apply(g), ErrClock) {
		t.Fatal("clock recovery silently re-enabled access")
	}
}

func TestRuntimeRotationAndInstanceEpoch(t *testing.T) {
	runtimeRotationAndInstanceEpoch(t, "vless_tls")
}
func TestHysteriaRuntimeRotationAndInstanceEpoch(t *testing.T) {
	runtimeRotationAndInstanceEpoch(t, "hy2_xray")
}
func runtimeRotationAndInstanceEpoch(t *testing.T, kind string) {
	r, ca, port := managedKind(t, kind)
	tcp, _ := echoes(t)
	g := Grant{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: time.Now().Add(time.Minute)}
	apply(t, r, g)
	a := startClient(t, kind, port, ca, users[0])
	f := openFlow(t, a, "tcp", tcp)
	check(t, f.exchange([]byte("old-key")), "setup")
	g.Generation++
	g.Credential = "33333333-3333-4333-8333-333333333333"
	apply(t, r, g)
	check(t, !f.exchange([]byte("old-flow")) && !one(t, a, "tcp", tcp), "rotation retained old credential")
	fresh := startClient(t, kind, port, ca, identity{users[0].Email, g.Credential})
	check(t, one(t, fresh, "tcp", tcp), "new credential failed")
	first, _ := r.Usage(g.ID)
	other, _, _ := managedKind(t, kind)
	apply(t, other, g)
	second, _ := other.Usage(g.ID)
	check(t, first.InstanceEpoch != second.InstanceEpoch && second.Uplink == nil, "engine epoch or empty counter incorrect")
}

func TestHysteriaOwnedShutdownClosesLiveCarriers(t *testing.T) {
	r, ca, port := managedKind(t, "hy2_xray")
	tcp, udp := echoes(t)
	for _, u := range users {
		apply(t, r, Grant{ID: u.Secret, Generation: 1, Enabled: true, Credential: u.Secret, ExpiresAt: time.Now().Add(time.Minute)})
	}
	a := startClient(t, "hy2_xray", port, ca, users[0])
	at, au := openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
	check(t, at.exchange([]byte("tcp")) && au.exchange([]byte("udp")), "setup")
	r.Close()
	check(t, !at.exchange([]byte("denied")) && !au.exchange([]byte("denied")) && at.outcome != "timeout" && au.outcome != "timeout", "owned shutdown retained carriers")
}
