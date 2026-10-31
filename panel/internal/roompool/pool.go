// Package roompool bounds the lifecycle of account media workers. It is not an
// authentication service: callers must derive Spec from verified node policy.
package roompool

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

var (
	ErrInvalid  = errors.New("room_invalid")
	ErrCapacity = errors.New("room_capacity")
	ErrConflict = errors.New("room_binding_conflict")
	ErrClosed   = errors.New("room_pool_closed")
	ErrExpired  = errors.New("room_expired")
	ErrDraining = errors.New("room_draining")
	ErrStartup  = errors.New("room_start_timeout")
	ErrWorker   = errors.New("room_worker_failed")
	ErrCooling  = errors.New("room_cooling_down")
)

type Spec struct {
	AccountID string // Authenticated account, not a credential or device ID.
	RoomID    string // Opaque routing revision (32 bytes, lowercase hex), not a URL.
}

// Runner must call ready only when the worker can accept authenticated traffic.
// It must keep running until termination, honor ctx and join ALL its children
// before returning. A cancellation request alone never proves resource cleanup.
// Provider errors are discarded; only fixed error codes leave this package.
type Runner func(ctx context.Context, spec Spec, ready func()) error

type Config struct {
	MaxWorkers      int
	MaxStarting     int
	StartupTimeout  time.Duration
	MaxLease        time.Duration
	MaxWait         time.Duration
	StartInterval   time.Duration
	RetryDelay      time.Duration // Each failed worker waits [RetryDelay, 2*RetryDelay).
	CircuitFailures int
	CircuitDelay    time.Duration // Also the healthy-ready interval that resets a failure streak.
}

type state uint8

const (
	queued state = iota
	starting
	ready
	draining
	cooling
	expired
)

type entry struct {
	spec          Spec
	state         state
	deadline      time.Time
	startDeadline time.Time
	healthyAfter  time.Time
	retryAt       time.Time
	running       bool
	startPermit   bool
	cancel        context.CancelFunc
	result        chan struct{}
	signaled      bool
	err           error
}

// Handle identifies this exact incarnation, including after it has expired.
// A stale handle cannot affect a later worker for the same account.
type Handle struct {
	pool  *Pool
	entry *entry
}

type Snapshot struct {
	Queued, Starting, Ready, Draining, Cooling int
	Total, StartPermits                        int
	CircuitOpen, Closed                        bool
}

type Pool struct {
	mu        sync.Mutex
	config    Config
	run       Runner
	entries   map[string]*entry
	queue     []*entry
	starting  int
	closed    bool
	failures  int
	blockedTo time.Time
	nextStart time.Time
	wake      chan struct{}
	done      chan struct{}
}

func New(c Config, run Runner) (*Pool, error) {
	if run == nil || c.MaxWorkers < 1 || c.MaxWorkers > 128 || c.MaxStarting < 1 || c.MaxStarting > c.MaxWorkers ||
		c.StartupTimeout <= 0 || c.StartupTimeout > time.Minute || c.MaxLease <= 0 || c.MaxLease > 5*time.Minute ||
		c.MaxWait <= 0 || c.MaxWait > time.Minute || c.StartInterval <= 0 || c.StartInterval > time.Minute ||
		c.RetryDelay <= 0 || c.RetryDelay > time.Minute || c.CircuitFailures < 1 || c.CircuitFailures > 128 ||
		c.CircuitDelay <= 0 || c.CircuitDelay > 5*time.Minute {
		return nil, ErrInvalid
	}
	p := &Pool{config: c, run: run, entries: make(map[string]*entry), wake: make(chan struct{}, 1), done: make(chan struct{})}
	go p.loop()
	return p, nil
}

func (p *Pool) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Admit is nonblocking and idempotent for a live binding. It does not renew an
// existing lease; callers must use Renew with a fresh verified policy deadline.
func (p *Pool) Admit(s Spec, ttl time.Duration) (Handle, error) {
	if !database.ValidID(s.AccountID) || !nodewire.ValidOLCKey(s.RoomID) || ttl <= 0 || ttl > p.config.MaxLease {
		return Handle{}, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return Handle{}, ErrClosed
	}
	now := time.Now()
	p.expireLocked(now)
	if old := p.entries[s.AccountID]; old != nil {
		if old.spec != s {
			return Handle{}, ErrConflict
		}
		if old.state == cooling {
			return Handle{}, ErrCooling
		}
		if old.state == draining {
			return Handle{}, ErrDraining
		}
		return Handle{p, old}, nil
	}
	if len(p.entries) >= p.config.MaxWorkers {
		return Handle{}, ErrCapacity
	}
	for _, owner := range p.entries {
		if owner.spec.RoomID == s.RoomID {
			// A misbound policy must not silently put two accounts in one room,
			// including while its previous worker is still draining.
			return Handle{}, ErrConflict
		}
	}
	e := &entry{spec: s, state: queued, deadline: now.Add(ttl), result: make(chan struct{})}
	p.entries[s.AccountID] = e
	p.queue = append(p.queue, e)
	p.notify()
	return Handle{p, e}, nil
}

func (p *Pool) owns(h Handle) bool { return h.pool == p && h.entry != nil }

// Wait never extends the lease or cancels a worker shared by another waiter.
func (p *Pool) Wait(ctx context.Context, h Handle) error {
	if !p.owns(h) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.MaxWait)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.mu.Lock()
		p.expireLocked(time.Now())
		e := h.entry
		err := e.err
		ok := e.state == ready
		p.mu.Unlock()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.result:
		}
	}
}

func (p *Pool) Renew(h Handle, ttl time.Duration) error {
	if !p.owns(h) || ttl <= 0 || ttl > p.config.MaxLease {
		return ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	now := time.Now()
	p.expireLocked(now)
	e := h.entry
	if p.entries[e.spec.AccountID] != e || e.state >= draining {
		return ErrExpired
	}
	e.deadline = now.Add(ttl)
	p.notify()
	return nil
}

// Release is idempotent. A running worker remains charged until its runner exits.
func (p *Pool) Release(h Handle) error {
	if !p.owns(h) {
		return ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e := h.entry
	if p.entries[e.spec.AccountID] == e {
		p.stopLocked(e, ErrDraining)
		p.notify()
	}
	return nil
}

func (p *Pool) signalLocked(e *entry) {
	if !e.signaled {
		e.signaled = true
		close(e.result)
	}
}

func (p *Pool) deleteLocked(e *entry) {
	if p.entries[e.spec.AccountID] == e {
		delete(p.entries, e.spec.AccountID)
	}
	e.state = expired
	// Remove queued tombstones immediately: repeated admit/release while a
	// provider is stuck must not grow the queue beyond MaxWorkers.
	for i, q := range p.queue {
		if q == e {
			copy(p.queue[i:], p.queue[i+1:])
			p.queue[len(p.queue)-1] = nil
			p.queue = p.queue[:len(p.queue)-1]
			break
		}
	}
}

func (p *Pool) stopLocked(e *entry, err error) {
	if e.state == expired {
		return
	}
	if e.err == nil {
		e.err = err
	}
	e.state = draining
	p.signalLocked(e)
	if e.cancel != nil {
		e.cancel()
	}
	if !e.running {
		p.deleteLocked(e)
	}
}

func (p *Pool) expireLocked(now time.Time) {
	for _, e := range p.entries {
		switch {
		case !now.Before(e.deadline):
			p.stopLocked(e, ErrExpired)
		case e.state == starting && !now.Before(e.startDeadline):
			p.stopLocked(e, ErrStartup)
		case e.state == cooling && !now.Before(e.retryAt):
			p.deleteLocked(e)
		case e.state == ready && !e.healthyAfter.IsZero() && !now.Before(e.healthyAfter):
			p.failures = 0
			e.healthyAfter = time.Time{}
		}
	}
}

func (p *Pool) loop() {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	defer close(p.done)
	for {
		p.mu.Lock()
		now := time.Now()
		p.expireLocked(now)
		if p.closed && len(p.entries) == 0 {
			p.mu.Unlock()
			return
		}
		if !p.closed && len(p.queue) > 0 && p.starting < p.config.MaxStarting && !now.Before(p.nextStart) && !now.Before(p.blockedTo) {
			e := p.queue[0]
			p.queue[0] = nil
			p.queue = p.queue[1:]
			ctx, cancel := context.WithCancel(context.Background())
			e.cancel, e.state, e.running, e.startPermit = cancel, starting, true, true
			e.startDeadline = now.Add(p.config.StartupTimeout)
			p.starting++
			p.nextStart = now.Add(p.config.StartInterval)
			go p.execute(ctx, e)
		}
		p.mu.Unlock()
		select {
		case <-p.wake:
		case <-tick.C:
		}
	}
}

func (p *Pool) execute(ctx context.Context, e *entry) {
	// A nil return without cancellation is also an unexpected worker exit.
	_ = p.run(ctx, e.spec, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.expireLocked(time.Now())
		if e.state != starting || ctx.Err() != nil {
			return
		}
		e.state = ready
		e.healthyAfter = time.Now().Add(p.config.CircuitDelay)
		e.startPermit = false
		p.starting--
		p.signalLocked(e)
		p.notify()
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	e.cancel()
	e.running = false
	if e.startPermit {
		e.startPermit = false
		p.starting--
	}
	failed := e.state != draining || e.err == ErrStartup
	if e.err == nil {
		e.err = ErrWorker
	}
	p.signalLocked(e)
	if !p.closed && failed && time.Now().Before(e.deadline) {
		p.failures++
		now := time.Now()
		if p.failures >= p.config.CircuitFailures {
			p.blockedTo = now.Add(p.config.CircuitDelay)
			p.failures = 0
		}
		e.state = cooling
		e.retryAt = now.Add(p.config.RetryDelay + time.Duration(rand.Int64N(int64(p.config.RetryDelay))))
	} else {
		p.deleteLocked(e)
	}
	p.notify()
}

func (p *Pool) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(time.Now())
	s := Snapshot{Total: len(p.entries), StartPermits: p.starting, Closed: p.closed, CircuitOpen: time.Now().Before(p.blockedTo)}
	for _, e := range p.entries {
		switch e.state {
		case queued:
			s.Queued++
		case starting:
			s.Starting++
		case ready:
			s.Ready++
		case draining:
			s.Draining++
		case cooling:
			s.Cooling++
		}
	}
	return s
}

// Close denies future admissions immediately. Deadline expiry reports that
// cleanup is unfinished; it never releases the charge for a stuck runner.
func (p *Pool) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	for _, e := range p.entries {
		p.stopLocked(e, ErrClosed)
	}
	p.notify()
	p.mu.Unlock()
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
