package xrayengine

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
)

func memoryUser(t *testing.T, u identity) *protocol.MemoryUser {
	t.Helper()
	v, err := (&protocol.User{Email: u.Email, Account: serial.ToTypedMessage(&vless.Account{Id: u.Secret, Encryption: "none"})}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAdmissionRevokeReaddIsolation(t *testing.T) {
	v := new(vless.MemoryValidator)
	defer v.Close()
	old := memoryUser(t, users[0])
	if err := v.Add(old); err != nil {
		t.Fatal(err)
	}
	var oldClosed, newClosed atomic.Int64
	entered, finish := make(chan struct{}), make(chan struct{})
	cleanup, err := v.Track(old, func() { oldClosed.Add(1); close(entered); <-finish })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- v.Del(old.Email) }()
	<-entered
	if _, err = v.Track(old, func() {}); err == nil {
		t.Fatal("authenticated stale incarnation admitted")
	}
	replacement := memoryUser(t, users[0])
	if err = v.Add(replacement); err != nil {
		t.Fatal(err)
	}
	release, err := v.Track(replacement, func() { newClosed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cleanup()
	close(finish)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if oldClosed.Load() != 1 || newClosed.Load() != 0 {
		t.Fatal("late old close touched re-add")
	}
	if err = v.Del(replacement.Email); err != nil {
		t.Fatal(err)
	}
	if newClosed.Load() != 1 {
		t.Fatal("replacement session not tracked")
	}
}

func TestConcurrentAdmissionAndRemoval(t *testing.T) {
	for n := 0; n < 50; n++ {
		v := new(vless.MemoryValidator)
		u := memoryUser(t, users[0])
		if err := v.Add(u); err != nil {
			t.Fatal(err)
		}
		var admitted, closed atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := v.Track(u, func() { closed.Add(1) }); err == nil {
					admitted.Add(1)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := v.Del(u.Email); err != nil {
				t.Error(err)
			}
		}()
		close(start)
		wg.Wait()
		if admitted.Load() != closed.Load() {
			t.Fatal("admission escaped revoke")
		}
		v.Close()
	}
}

func TestDuplicateNormalizedCredentialRejected(t *testing.T) {
	v := new(vless.MemoryValidator)
	defer v.Close()
	u := memoryUser(t, users[0])
	if err := v.Add(u); err != nil {
		t.Fatal(err)
	}
	duplicate := users[0]
	duplicate.Email = "different@b0.invalid"
	if err := v.Add(memoryUser(t, duplicate)); err == nil {
		t.Fatal("duplicate UUID allowed")
	}
	if v.GetCount() != 1 {
		t.Fatal("partial duplicate inserted")
	}
}

func TestRealVLESSActiveRevokeAndCounters(t *testing.T)    { realRevoke(t, "vless_tls") }
func TestRealHysteriaActiveRevokeAndCounters(t *testing.T) { realRevoke(t, "hy2_xray") }
func realRevoke(t *testing.T, kind string) {
	ca := syntheticCert(t)
	s := startServer(t, kind, ca)
	for _, u := range users {
		s.change(t, kind, u, true)
	}
	check(t, strings.Join(s.userList(t), ",") == users[0].Email+","+users[1].Email, "add read-back")
	tcp, udp := echoes(t)
	a, b := startClient(t, kind, s.port, ca, users[0]), startClient(t, kind, s.port, ca, users[1])
	at, au := openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
	bt, bu := openFlow(t, b, "tcp", tcp), openFlow(t, b, "udp", udp)
	check(t, at.exchange(bytes.Repeat([]byte("A"), 4096)) && bt.exchange(bytes.Repeat([]byte("B"), 8192)), "TCP payload")
	before := s.counters(t, false)
	check(t, au.exchange([]byte("A-datagram")) && bu.exchange([]byte("B-datagram")), "UDP payload")
	after := s.counters(t, false)
	for _, u := range users {
		for _, direction := range []string{"uplink", "downlink"} {
			key := trafficKey(u.Email, direction)
			check(t, before[key] >= 4096 && after[key] > before[key], "live per-user counters")
		}
	}
	start := time.Now()
	s.change(t, kind, users[0], false)
	check(t, len(s.userList(t)) == 1, "remove read-back")
	check(t, !at.exchange([]byte("revoked-old-tcp")) && !au.exchange([]byte("revoked-old-udp")), "old A survived revoke")
	check(t, at.outcome != "timeout" && au.outcome != "timeout", "revoke must terminate, not wait for probe timeout")
	check(t, time.Since(start) < deadline, "active revoke exceeded bound")
	check(t, !one(t, a, "tcp", tcp) && !one(t, a, "udp", udp), "saved A credential still accepted")
	check(t, bt.exchange([]byte("B-still-tcp")) && bu.exchange([]byte("B-still-udp")) && one(t, b, "tcp", tcp) && one(t, b, "udp", udp), "B disrupted")
	s.change(t, kind, users[0], true)
	check(t, one(t, a, "tcp", tcp) && one(t, a, "udp", udp), "readd failed")
	check(t, bt.exchange([]byte("B-final-tcp")) && bu.exchange([]byte("B-final-udp")), "readd disrupted B")
	t.Log("Real managed A/B TCP+UDP: live counters, existing A terminated, saved A denied, B intact, re-add PASS")
}
