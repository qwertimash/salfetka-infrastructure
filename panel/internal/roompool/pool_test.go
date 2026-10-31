package roompool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{MaxWorkers: 100, MaxStarting: 4, StartupTimeout: time.Second, MaxLease: time.Minute,
		MaxWait: 5 * time.Second, StartInterval: time.Millisecond, RetryDelay: 100 * time.Millisecond,
		CircuitFailures: 3, CircuitDelay: 200 * time.Millisecond}
}
func spec(i int) Spec {
	return Spec{AccountID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), RoomID: fmt.Sprintf("%064x", i)}
}
func newPool(t *testing.T, c Config, run Runner) *Pool {
	t.Helper()
	p, err := New(c, run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.Close(ctx); err != nil {
			t.Errorf("cleanup: %v %+v", err, p.Snapshot())
		}
	})
	return p
}
func admit(t *testing.T, p *Pool, s Spec, ttl time.Duration) Handle {
	t.Helper()
	h, err := p.Admit(s, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func wait(t *testing.T, p *Pool, h Handle) {
	t.Helper()
	if err := p.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func live(ctx context.Context, _ Spec, ready func()) error {
	ready()
	<-ctx.Done()
	return ctx.Err()
}

func TestHundredWorkersIsolationAndCleanup(t *testing.T) {
	var running, maximum, joined atomic.Int32
	var mu sync.Mutex
	stops := map[string]int{}
	p := newPool(t, testConfig(), func(ctx context.Context, s Spec, ready func()) error {
		n := running.Add(1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		joined.Add(1)
		ready()
		<-ctx.Done()
		mu.Lock()
		stops[s.AccountID]++
		mu.Unlock()
		running.Add(-1)
		return nil
	})
	handles := make([]Handle, 100)
	var wg sync.WaitGroup
	for i := range handles {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h, err := p.Admit(spec(i+1), 30*time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			handles[i] = h
		}(i)
	}
	wg.Wait()
	if _, err := p.Admit(spec(101), 30*time.Second); err != ErrCapacity {
		t.Fatalf("capacity: %v", err)
	}
	for _, h := range handles {
		wait(t, p, h)
	}
	if s := p.Snapshot(); s.Ready != 100 || s.Total != 100 || s.StartPermits != 0 || maximum.Load() != 100 {
		t.Fatalf("100 workers: %+v max=%d", s, maximum.Load())
	}
	_ = p.Release(handles[0])
	eventually(t, func() bool { return p.Snapshot().Total == 99 })
	for _, h := range handles[1:] {
		wait(t, p, h)
	}
	mu.Lock()
	if len(stops) != 1 || stops[spec(1).AccountID] != 1 {
		t.Errorf("A drain affected others: %v", stops)
	}
	mu.Unlock()
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if running.Load() != 0 || joined.Load() != 100 || p.Snapshot().Total != 0 {
		t.Fatal("workers leaked")
	}
	if _, err := p.Admit(spec(102), time.Second); err != ErrClosed {
		t.Fatalf("admission after close: %v", err)
	}
}

func TestIdempotenceBindingAndStaleHandle(t *testing.T) {
	var starts atomic.Int32
	p := newPool(t, testConfig(), func(ctx context.Context, s Spec, ready func()) error {
		starts.Add(1)
		ready()
		ready() // A duplicate provider notification cannot release a second permit.
		<-ctx.Done()
		return nil
	})
	a := admit(t, p, spec(1), 10*time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := p.Admit(spec(1), 10*time.Second)
			if h != a || err != nil {
				t.Errorf("duplicate binding: %v", err)
			}
		}()
	}
	wg.Wait()
	wait(t, p, a)
	other := spec(1)
	other.RoomID = strings.Repeat("b", 64)
	if _, err := p.Admit(other, time.Second); err != ErrConflict {
		t.Fatalf("room change did not drain: %v", err)
	}
	_ = p.Release(a)
	eventually(t, func() bool { return p.Snapshot().Total == 0 })
	b := admit(t, p, other, 10*time.Second)
	wait(t, p, b)
	_ = p.Release(a)
	if err := p.Renew(a, time.Second); err != ErrExpired {
		t.Fatalf("stale renewal: %v", err)
	}
	wait(t, p, b)
	if starts.Load() != 2 || p.Snapshot().StartPermits != 0 {
		t.Fatal("duplicate starts or permit underflow")
	}
}

func TestStartupTimeoutRetainsPermitAndCapacityUntilExit(t *testing.T) {
	c := testConfig()
	c.MaxWorkers, c.MaxStarting, c.StartupTimeout = 2, 1, 40*time.Millisecond
	entered, unblock := make(chan struct{}), make(chan struct{})
	p := newPool(t, c, func(ctx context.Context, s Spec, ready func()) error {
		if s.AccountID == spec(1).AccountID {
			close(entered)
			<-unblock // Deliberately non-cooperative provider.
			ready()   // Stale success must not revive a timed-out worker.
			return nil
		}
		return live(ctx, s, ready)
	})
	defer close(unblock)
	a := admit(t, p, spec(1), time.Second)
	<-entered
	b := admit(t, p, spec(2), 100*time.Millisecond)
	if err := p.Wait(context.Background(), a); err != ErrStartup {
		t.Fatalf("startup: %v", err)
	}
	if s := p.Snapshot(); s.Draining != 1 || s.StartPermits != 1 || s.Queued != 1 {
		t.Fatalf("unconfirmed stop released capacity: %+v", s)
	}
	if _, err := p.Admit(spec(3), time.Second); err != ErrCapacity {
		t.Fatalf("over-admission: %v", err)
	}
	if err := p.Wait(context.Background(), b); err != ErrExpired {
		t.Fatalf("queued lease: %v", err)
	}
	if err := p.Renew(b, time.Second); err != ErrExpired {
		t.Fatalf("queued revival: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("false cleanup success: %v", err)
	}
	if s := p.Snapshot(); s.Total != 1 || s.StartPermits != 1 || !s.Closed {
		t.Fatalf("blocked cleanup accounting: %+v", s)
	}
}

func TestWaitCancellationDoesNotCancelWorker(t *testing.T) {
	c := testConfig()
	c.MaxWait = 20 * time.Millisecond
	entered, start := make(chan struct{}), make(chan struct{})
	p := newPool(t, c, func(ctx context.Context, _ Spec, ready func()) error {
		close(entered)
		select {
		case <-start:
			ready()
		case <-ctx.Done():
		}
		<-ctx.Done()
		return nil
	})
	h := admit(t, p, spec(1), time.Second)
	<-entered
	if err := p.Wait(context.Background(), h); err != context.DeadlineExceeded {
		t.Fatalf("unbounded wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Wait(ctx, h); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
	if s := p.Snapshot(); s.Starting != 1 {
		t.Fatalf("waiter killed shared worker: %+v", s)
	}
	close(start)
	eventually(t, func() bool { return p.Snapshot().Ready == 1 })
	wait(t, p, h)
}

func TestStartupConcurrencyAndQueueBoundedUnderChurn(t *testing.T) {
	c := testConfig()
	c.MaxWorkers, c.MaxStarting = 5, 2
	var running atomic.Int32
	p := newPool(t, c, func(ctx context.Context, _ Spec, _ func()) error {
		running.Add(1)
		defer running.Add(-1)
		<-ctx.Done()
		return nil
	})
	admit(t, p, spec(1), time.Minute)
	admit(t, p, spec(2), time.Minute)
	eventually(t, func() bool { return running.Load() == 2 })
	for i := 3; i < 1003; i++ {
		h := admit(t, p, spec(i), time.Minute)
		_ = p.Release(h)
	}
	p.mu.Lock()
	n := len(p.queue)
	p.mu.Unlock()
	if n != 0 || running.Load() != 2 || p.Snapshot().StartPermits != 2 {
		t.Fatalf("queue growth or concurrency escape: queue=%d %+v", n, p.Snapshot())
	}
}

func TestProviderFailureCooldownCircuitAndNoAutomaticRetry(t *testing.T) {
	c := testConfig()
	c.CircuitFailures, c.CircuitDelay, c.RetryDelay = 1, 180*time.Millisecond, 20*time.Millisecond
	var calls atomic.Int32
	p := newPool(t, c, func(ctx context.Context, s Spec, ready func()) error {
		if calls.Add(1) == 1 {
			return errors.New("private provider URL and credential must not escape")
		}
		return live(ctx, s, ready)
	})
	a := admit(t, p, spec(1), time.Second)
	if err := p.Wait(context.Background(), a); err != ErrWorker {
		t.Fatalf("provider error leaked: %v", err)
	}
	if _, err := p.Admit(spec(1), time.Second); err != ErrCooling {
		t.Fatalf("no retry cooldown: %v", err)
	}
	if !p.Snapshot().CircuitOpen {
		t.Fatal("circuit did not open")
	}
	b := admit(t, p, spec(2), time.Second)
	time.Sleep(70 * time.Millisecond)
	if calls.Load() != 1 || p.Snapshot().Queued != 1 {
		t.Fatal("circuit bypassed or automatic retry")
	}
	wait(t, p, b)
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatal("failed A retried without policy reconciliation")
	}
	a2 := admit(t, p, spec(1), time.Second)
	wait(t, p, a2)
	_ = p.Release(a)
	wait(t, p, a2)
}

func TestStartSpacingAndMonotonicLeaseExpiry(t *testing.T) {
	c := testConfig()
	c.StartInterval = 30 * time.Millisecond
	var mu sync.Mutex
	var starts []time.Time
	p := newPool(t, c, func(ctx context.Context, s Spec, ready func()) error {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		return live(ctx, s, ready)
	})
	var handles []Handle
	for i := 1; i <= 4; i++ {
		handles = append(handles, admit(t, p, spec(i), time.Second))
	}
	for _, h := range handles {
		wait(t, p, h)
	}
	mu.Lock()
	for i := 1; i < len(starts); i++ {
		if starts[i].Sub(starts[i-1]) < 25*time.Millisecond {
			t.Errorf("start burst: %v", starts[i].Sub(starts[i-1]))
		}
	}
	mu.Unlock()
	if err := p.Renew(handles[0], 25*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return p.Snapshot().Total == 3 })
	if err := p.Wait(context.Background(), handles[0]); err != ErrExpired {
		t.Fatalf("expired worker: %v", err)
	}
	for _, h := range handles[1:] {
		wait(t, p, h)
	}
}

func TestValidationAndForeignHandles(t *testing.T) {
	c := testConfig()
	for _, bad := range []Config{{}, {MaxWorkers: 1000}, c} {
		if _, err := New(bad, nil); err != ErrInvalid {
			t.Fatal("nil runner accepted")
		}
	}
	p := newPool(t, c, live)
	q := newPool(t, c, live)
	h := admit(t, p, spec(1), time.Second)
	collision := spec(2)
	collision.RoomID = spec(1).RoomID
	if _, err := p.Admit(collision, time.Second); err != ErrConflict {
		t.Fatal("room assigned to two accounts")
	}
	if err := q.Release(h); err != ErrInvalid {
		t.Fatal("foreign release")
	}
	if err := q.Renew(h, time.Second); err != ErrInvalid {
		t.Fatal("foreign renew")
	}
	if err := q.Wait(context.Background(), h); err != ErrInvalid {
		t.Fatal("foreign wait")
	}
	if _, err := p.Admit(Spec{AccountID: "device-supplied", RoomID: "secret URL"}, time.Second); err != ErrInvalid {
		t.Fatal("invalid identity")
	}
	if _, err := p.Admit(spec(2), 6*time.Minute); err != ErrInvalid {
		t.Fatal("unbounded lease")
	}
}

// This exercises cancellation while real local byte streams are in use. It is
// not a Jitsi, encryption, network throughput or account-takeover benchmark.
func TestDrainDuringTrafficKeepsOtherWorker(t *testing.T) {
	var mu sync.Mutex
	clients := map[string]net.Conn{}
	p := newPool(t, testConfig(), func(ctx context.Context, s Spec, ready func()) error {
		client, server := net.Pipe()
		mu.Lock()
		clients[s.AccountID] = client
		mu.Unlock()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(server, server)
		}()
		ready()
		<-ctx.Done()
		_ = server.Close()
		_ = client.Close()
		<-done // The permit must cover all of the worker's children.
		return nil
	})
	a := admit(t, p, spec(1), 10*time.Second)
	b := admit(t, p, spec(2), 10*time.Second)
	wait(t, p, a)
	wait(t, p, b)
	mu.Lock()
	ac, bc := clients[spec(1).AccountID], clients[spec(2).AccountID]
	mu.Unlock()
	_ = ac.SetDeadline(time.Now().Add(3 * time.Second))
	_ = bc.SetDeadline(time.Now().Add(3 * time.Second))
	var aBytes atomic.Int64
	aDone := make(chan error, 1)
	go func() {
		payload, reply := bytes.Repeat([]byte{42}, 16*1024), make([]byte, 16*1024)
		for {
			if _, err := ac.Write(payload); err != nil {
				aDone <- err
				return
			}
			if _, err := io.ReadFull(ac, reply); err != nil {
				aDone <- err
				return
			}
			if !bytes.Equal(payload, reply) {
				aDone <- errors.New("corrupted A data")
				return
			}
			aBytes.Add(int64(len(reply)))
		}
	}()
	eventually(t, func() bool { return aBytes.Load() >= 256*1024 })
	for i := 0; i < 40; i++ {
		if i == 20 {
			_ = p.Release(a)
			select {
			case err := <-aDone:
				if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
					t.Fatalf("A did not close cleanly: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("A traffic survived drain")
			}
		}
		payload := []byte(fmt.Sprintf("B packet %d", i))
		if _, err := bc.Write(payload); err != nil {
			t.Fatalf("B write %d: %v", i, err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(bc, reply); err != nil || !bytes.Equal(payload, reply) {
			t.Fatalf("B response %d: %v", i, err)
		}
	}
	wait(t, p, b)
	eventually(t, func() bool { return p.Snapshot().Total == 1 })
}

func TestReadyWorkerCrashIsReportedAndNeverRestartsItself(t *testing.T) {
	crash := make(chan struct{})
	var starts atomic.Int32
	p := newPool(t, testConfig(), func(ctx context.Context, _ Spec, ready func()) error {
		starts.Add(1)
		ready()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-crash:
			return nil // Even an unexpected 'successful' return means a dead worker.
		}
	})
	h := admit(t, p, spec(1), time.Second)
	wait(t, p, h)
	close(crash)
	eventually(t, func() bool { return p.Snapshot().Cooling == 1 })
	if err := p.Wait(context.Background(), h); err != ErrWorker {
		t.Fatalf("crashed worker remained ready: %v", err)
	}
	if err := p.Renew(h, time.Second); err != ErrExpired {
		t.Fatalf("crashed worker renewed: %v", err)
	}
	eventually(t, func() bool { return p.Snapshot().Total == 0 })
	if starts.Load() != 1 {
		t.Fatal("automatic restart without policy")
	}
}

func TestBriefReadinessCannotBypassFailureCircuit(t *testing.T) {
	c := testConfig()
	c.CircuitFailures, c.CircuitDelay = 2, time.Second
	var calls atomic.Int32
	p := newPool(t, c, func(_ context.Context, _ Spec, ready func()) error {
		calls.Add(1)
		ready()
		return errors.New("provider flapped immediately after readiness")
	})
	for i := 1; i <= 2; i++ {
		admit(t, p, spec(i), 2*time.Second)
		eventually(t, func() bool { return p.Snapshot().Cooling == i })
	}
	if !p.Snapshot().CircuitOpen {
		t.Fatal("flapping provider reset failure streak before becoming stable")
	}
	admit(t, p, spec(3), 100*time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatal("start passed an open circuit")
	}
}
