package bypasslease

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"salfetka/panel/internal/database/dbtest"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	c, e := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	s, e := ln.Accept()
	if e != nil {
		c.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}
func echo(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, e := c.Write([]byte("B alive")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 7)
	if _, e := io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	if string(b) != "B alive" {
		t.Fatal("corrupt echo")
	}
}
func TestAccountTakeoverDuringTCPBulkPreservesOtherAccount(t *testing.T) {
	p := dbtest.New(t)
	s := &Store{Pool: p}
	ctx := context.Background()
	u := account(t, p)
	a, a2 := owner(t, p, u), owner(t, p, u)
	b := owner(t, p, account(t, p))
	la, lb := active(t, s, a), active(t, s, b)
	g := NewGates(100)
	t.Cleanup(func() {
		if e := g.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	for _, l := range []Lease{la, lb} {
		if e := g.Apply(l.Ref, l.Revision, time.Now(), LeaseTTL); e != nil {
			t.Fatal(e)
		}
	}
	ac, as := tcpPair(t)
	bc, bs := tcpPair(t)
	for i, conn := range []net.Conn{as, bs} {
		ref := []Ref{la.Ref, lb.Ref}[i]
		release, e := g.Track(ref, func(context.Context) error { return conn.Close() })
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(release)
	}
	bDone := make(chan struct{})
	go func() { defer close(bDone); io.Copy(bs, bs) }()
	defer func() { bs.Close(); <-bDone }()
	echo(t, bc)
	var received atomic.Int64
	reader := make(chan error, 1)
	writer := make(chan error, 1)
	go func() {
		defer close(reader)
		buf := make([]byte, 32*1024)
		for {
			n, e := as.Read(buf)
			received.Add(int64(n))
			if e != nil {
				reader <- e
				return
			}
		}
	}()
	go func() {
		defer close(writer)
		buf := bytes.Repeat([]byte("a"), 32*1024)
		for {
			if _, e := ac.Write(buf); e != nil {
				writer <- e
				return
			}
		}
	}()
	defer func() { ac.Close(); as.Close(); <-reader; <-writer }()
	until := time.Now().Add(2 * time.Second)
	for received.Load() < 256*1024 {
		if time.Now().After(until) {
			t.Fatal("bulk not active")
		}
		time.Sleep(time.Millisecond)
	}
	echo(t, bc) // Same B connection also carries data during A's bulk transfer.
	next, e := s.ClaimExplicit(ctx, a2, id(t))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Activate(ctx, a2, next.Ref); !errors.Is(e, ErrPending) {
		t.Fatal(e)
	}
	if e = g.Drain(ctx, la.Ref); e != nil {
		t.Fatal(e)
	}
	// Confirm both ends actually stop before acknowledging closure centrally.
	for _, stopped := range []<-chan error{reader, writer} {
		select {
		case err := <-stopped:
			if err == nil {
				t.Fatal("bulk did not terminate on closure")
			}
		case <-time.After(time.Second):
			t.Fatal("bulk still running after drain")
		}
	}
	if _, e = g.Track(la.Ref, func(context.Context) error { return nil }); !errors.Is(e, ErrStale) {
		t.Fatal("old admission reopened", e)
	}
	if _, e = s.AcknowledgeClosed(ctx, a, la.Ref); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Activate(ctx, a2, next.Ref); e != nil {
		t.Fatal(e)
	}
	g2 := NewGates(1)
	t.Cleanup(func() { g2.Close(ctx) })
	if e = g2.Apply(next.Ref, 1, time.Now(), LeaseTTL); e != nil {
		t.Fatal(e)
	}
	nc, ns := tcpPair(t)
	release, e := g2.Track(next.Ref, func(context.Context) error { return ns.Close() })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(release)
	nDone := make(chan struct{})
	go func() { defer close(nDone); io.Copy(ns, ns) }()
	defer func() { ns.Close(); <-nDone }()
	echo(t, nc)
	for i := 0; i < 10; i++ {
		echo(t, bc)
	}
	status, e := s.Status(ctx, a, la.Ref)
	if e != nil || status.Reason != Replaced {
		t.Fatal("replacement reason lost", status, e)
	}
	t.Logf("A actively transmitted %d bytes, replaced after drain; B same TCP survived", received.Load())
}

func TestGateCloseFailureNeverProducesAcknowledgement(t *testing.T) {
	g := NewGates(2)
	r := Ref{id(t), 1}
	ctx := context.Background()
	if e := g.Apply(r, 1, time.Now(), LeaseTTL); e != nil {
		t.Fatal(e)
	}
	var fail atomic.Bool
	fail.Store(true)
	_, e := g.Track(r, func(context.Context) error {
		if fail.Load() {
			return errors.New("test close failed")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = g.Drain(ctx, r); !errors.Is(e, ErrNotDrained) {
		t.Fatal(e)
	}
	if e = g.Apply(Ref{r.UserID, 2}, 1, time.Now(), LeaseTTL); !errors.Is(e, ErrPending) {
		t.Fatal("replacement before close", e)
	}
	if e = g.Apply(r, 2, time.Now(), LeaseTTL); !errors.Is(e, ErrStale) {
		t.Fatal("denied renewal", e)
	}
	fail.Store(false)
	if e = g.Drain(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e = g.Apply(Ref{r.UserID, 2}, 1, time.Now(), LeaseTTL); e != nil {
		t.Fatal(e)
	}
	if e = g.Apply(r, 99, time.Now(), LeaseTTL); !errors.Is(e, ErrStale) {
		t.Fatal("old generation returned", e)
	}
	if e = g.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestGateExpiryDuplicateAndDelayedResponse(t *testing.T) {
	g := NewGates(2)
	t.Cleanup(func() { g.Close(context.Background()) })
	r := Ref{id(t), 1}
	if e := g.Apply(r, 1, time.Now().Add(-time.Minute), LeaseTTL); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	if e := g.Apply(r, 1, time.Now(), 120*time.Millisecond); e != nil {
		t.Fatal(e)
	}
	closed := make(chan struct{})
	var once sync.Once
	if _, e := g.Track(r, func(context.Context) error { once.Do(func() { close(closed) }); return nil }); e != nil {
		t.Fatal(e)
	}
	if e := g.Apply(r, 1, time.Now(), LeaseTTL); e != nil {
		t.Fatal(e)
	} // same revision cannot extend
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("duplicate extended expiry")
	}
	if e := g.Apply(r, 2, time.Now(), LeaseTTL); !errors.Is(e, ErrStale) {
		t.Fatal("expired gate resurrected", e)
	}
}

func TestConcurrentTrackAndDrain(t *testing.T) {
	g := NewGates(1)
	r := Ref{id(t), 1}
	ctx := context.Background()
	if e := g.Apply(r, 1, time.Now(), LeaseTTL); e != nil {
		t.Fatal(e)
	}
	var accepted, closed atomic.Int64
	if _, e := g.Track(r, func(context.Context) error { closed.Add(1); return nil }); e != nil {
		t.Fatal(e)
	}
	accepted.Add(1)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, e := g.Track(r, func(context.Context) error { closed.Add(1); return nil }); e == nil {
				accepted.Add(1)
			} else if !errors.Is(e, ErrStale) {
				t.Error(e)
			}
		}()
	}
	close(start)
	if e := g.Drain(ctx, r); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	if e := g.Drain(ctx, r); e != nil {
		t.Fatal(e)
	}
	if accepted.Load() != closed.Load() {
		t.Fatal("unclosed admission", accepted.Load(), closed.Load())
	}
	if e := g.Apply(Ref{id(t), 1}, 1, time.Now(), LeaseTTL); !errors.Is(e, ErrCapacity) {
		t.Fatal("tombstone silently discarded", e)
	}
	if e := g.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestUDPDrainAndCancelledClose(t *testing.T) {
	g := NewGates(2)
	t.Cleanup(func() { g.Close(context.Background()) })
	refs := []Ref{{id(t), 1}, {id(t), 1}}
	servers := make([]net.PacketConn, 2)
	clients := make([]net.PacketConn, 2)
	for i, r := range refs {
		if e := g.Apply(r, 1, time.Now(), LeaseTTL); e != nil {
			t.Fatal(e)
		}
		var e error
		servers[i], e = net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		clients[i], e = net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		s, c := servers[i], clients[i]
		t.Cleanup(func() { s.Close(); c.Close() })
		release, e := g.Track(r, func(context.Context) error { return s.Close() })
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(release)
	}
	exchange := func(i int) {
		s, c := servers[i], clients[i]
		s.SetDeadline(time.Now().Add(time.Second))
		c.SetDeadline(time.Now().Add(time.Second))
		if _, e := c.WriteTo([]byte("udp"), s.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 32)
		n, peer, e := s.ReadFrom(b)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.WriteTo(b[:n], peer); e != nil {
			t.Fatal(e)
		}
		n, _, e = c.ReadFrom(b)
		if e != nil || string(b[:n]) != "udp" {
			t.Fatal("UDP echo", e)
		}
	}
	exchange(0)
	exchange(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := g.Drain(ctx, refs[0]); !errors.Is(e, ErrNotDrained) {
		t.Fatal("cancelled drain ACK", e)
	}
	if _, e := g.Track(refs[0], func(context.Context) error { return nil }); !errors.Is(e, ErrStale) {
		t.Fatal("denial lost", e)
	}
	if e := g.Drain(context.Background(), refs[0]); e != nil {
		t.Fatal(e)
	}
	if _, _, e := servers[0].ReadFrom(make([]byte, 32)); !errors.Is(e, net.ErrClosed) {
		t.Fatal("UDP not closed", e)
	}
	exchange(1)
}

func TestRenewalReplacesOldExpiryTimer(t *testing.T) {
	g := NewGates(1)
	t.Cleanup(func() { g.Close(context.Background()) })
	r := Ref{id(t), 1}
	if e := g.Apply(r, 1, time.Now(), 100*time.Millisecond); e != nil {
		t.Fatal(e)
	}
	closed := make(chan struct{})
	var once sync.Once
	if _, e := g.Track(r, func(context.Context) error { once.Do(func() { close(closed) }); return nil }); e != nil {
		t.Fatal(e)
	}
	if e := g.Apply(r, 2, time.Now(), time.Second); e != nil {
		t.Fatal(e)
	}
	select {
	case <-closed:
		t.Fatal("old timer drained renewal")
	case <-time.After(150 * time.Millisecond):
	}
	if e := g.Drain(context.Background(), r); e != nil {
		t.Fatal(e)
	}
}
