package xrayengine

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This tests the authenticated engine hook with a local budget, not deployment
// or the distributed controller. Existing A connections must pass the hook
// after activation; B and release must not require an engine restart.
func TestAntifraudExistingTrafficAndIsolation(t *testing.T) {
	for _, kind := range []string{"vless_tls", "hy2_xray"} {
		t.Run(kind, func(t *testing.T) {
			var limited atomic.Bool
			var mu sync.Mutex
			var next time.Time
			var up, down atomic.Int64
			gate := func(ctx context.Context, grant, direction string, size int) error {
				if grant != users[0].Secret {
					return nil
				}
				if direction == "upload" {
					up.Add(int64(size))
				} else if direction == "download" {
					down.Add(int64(size))
				} else {
					t.Error("invalid direction")
				}
				if !limited.Load() {
					return nil
				}
				mu.Lock()
				start := time.Now()
				if next.After(start) {
					start = next
				}
				next = start.Add(time.Duration(size) * 8 * time.Second / 1000000)
				wait := time.Until(next)
				mu.Unlock()
				timer := time.NewTimer(wait)
				defer timer.Stop()
				select {
				case <-timer.C:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			ca := syntheticCert(t)
			port := freePort(t, kind == "hy2_xray")
			backend := ""
			if kind == "hy2_xray" {
				backend = "hysteria2"
			}
			r, err := New(Config{Backend: backend, ListenIP: "127.0.0.1", Port: port, CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n"), LabLoopbackOnly: true, TrafficGate: gate})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			for _, u := range users {
				apply(t, r, Grant{ID: u.Secret, Credential: u.Secret, Generation: 1, Enabled: true, ExpiresAt: time.Now().Add(time.Minute)})
			}
			tcp, udp := echoes(t)
			a, b := startClient(t, kind, port, ca, users[0]), startClient(t, kind, port, ca, users[1])
			at, au := openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
			bt, bu := openFlow(t, b, "tcp", tcp), openFlow(t, b, "udp", udp)
			if !at.exchange([]byte("before")) || !au.exchange([]byte("udp-before")) || !bt.exchange([]byte("B-before")) {
				t.Fatal("initial connection")
			}
			limited.Store(true)
			beforeUp, beforeDown := up.Load(), down.Load()
			payload := bytes.Repeat([]byte("x"), 64*1024)
			started := time.Now()
			done := make(chan bool, 1)
			go func() { done <- at.exchange(payload) }()
			bstarted := time.Now()
			if !bt.exchange([]byte("B-during")) || !bu.exchange([]byte("B-udp-during")) {
				t.Fatal("A affected B")
			}
			if time.Since(bstarted) > 500*time.Millisecond {
				t.Fatal("B queued behind A")
			}
			if !<-done {
				t.Fatal("limited A lost data", at.outcome)
			}
			elapsed := time.Since(started)
			if elapsed < time.Second || elapsed > 2500*time.Millisecond {
				t.Fatal("shared up+down rate not applied", elapsed)
			}
			if up.Load()-beforeUp < int64(len(payload)) || down.Load()-beforeDown < int64(len(payload)) {
				t.Fatal("authenticated traffic bypassed hook")
			}
			// Datagram boundaries remain intact while the hook is active.
			if !au.exchange(bytes.Repeat([]byte("u"), 1300)) {
				t.Fatal("UDP changed boundary")
			}
			limited.Store(false)
			started = time.Now()
			if !at.exchange(payload) || time.Since(started) > 500*time.Millisecond {
				t.Fatal("release failed on existing stream")
			}
			if !bt.exchange([]byte("B-after")) {
				t.Fatal("B disconnected")
			}
			t.Logf("%s: A 64KiB upload+64KiB download %s; B and existing-stream release passed", kind, elapsed)
		})
	}
}
