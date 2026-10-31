package bypasslease

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNotDrained = errors.New("bypass_connections_not_closed")
var ErrCapacity = errors.New("bypass_gate_capacity")

type closeFlow func(context.Context) error
type gate struct {
	ref      Ref
	revision int64
	until    time.Time
	denied   bool
	flows    map[uint64]closeFlow
	timer    *time.Timer
	drain    sync.Mutex
}

// Gates enforces local admission and tracks live TCP/UDP closers. It does not
// authenticate grants. C1c must verify node/epoch, the response's request nonce
// and its remaining lifetime before Apply; no caller is wired in runtime yet.
// Keep tombstones for this engine incarnation: do not recreate Gates on reconnect.
type Gates struct {
	mu     sync.Mutex
	rooms  map[string]*gate
	max    int
	next   uint64
	closed bool
}

func NewGates(maxAccounts int) *Gates { return &Gates{rooms: make(map[string]*gate), max: maxAccounts} }

// started must be captured before the authenticated control request. A delayed
// response never receives a new full TTL. budget is verified remaining validity,
// bounded by LeaseTTL. Both values are local call metadata, not client JSON.
func (g *Gates) Apply(ref Ref, revision int64, started time.Time, budget time.Duration) error {
	now := time.Now()
	if !ref.valid() || revision < 1 || revision > MaxSequence || started.IsZero() || started.After(now) || budget <= 0 || budget > LeaseTTL {
		return ErrInvalid
	}
	until := started.Add(budget)
	if !until.After(now) {
		return ErrExpired
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrStale
	}
	old := g.rooms[ref.UserID]
	if old != nil {
		if ref.Generation < old.ref.Generation {
			return ErrStale
		}
		if ref.Generation == old.ref.Generation {
			if old.denied || !old.until.After(now) || revision < old.revision {
				return ErrStale
			}
			if revision == old.revision {
				return nil
			} // duplicate cannot extend deadline
		} else if !old.denied || len(old.flows) > 0 {
			return ErrPending
		}
	} else if g.max <= 0 || len(g.rooms) >= g.max {
		return ErrCapacity
	}
	if old != nil && old.timer != nil {
		old.timer.Stop()
	}
	current := old
	if old == nil || old.ref != ref {
		current = &gate{ref: ref, flows: make(map[uint64]closeFlow)}
		g.rooms[ref.UserID] = current
	}
	current.revision = revision
	current.until = until
	current.timer = time.AfterFunc(time.Until(until), func() {
		// A stopped timer can already be running. Do not drain a newer renewal.
		g.mu.Lock()
		valid := g.rooms[ref.UserID] == current && current.revision == revision
		if valid {
			current.denied = true
		}
		g.mu.Unlock()
		if valid {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = g.Drain(ctx, ref)
		}
	})
	return nil
}

// Track must be called before allowing a flow to carry data. release is called
// only after that flow has actually closed, not merely after requesting closure.
func (g *Gates) Track(ref Ref, close func(context.Context) error) (func(), error) {
	if close == nil {
		return nil, ErrInvalid
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	x := g.rooms[ref.UserID]
	if g.closed || x == nil || x.ref != ref || x.denied || !x.until.After(time.Now()) {
		return nil, ErrStale
	}
	g.next++
	id := g.next
	x.flows[id] = close
	return func() { g.mu.Lock(); delete(x.flows, id); g.mu.Unlock() }, nil
}

// Drain returns nil only after every tracked close has succeeded. Denial is
// irrevocable for this generation, including when a close errors or ctx ends.
func (g *Gates) Drain(ctx context.Context, ref Ref) error {
	g.mu.Lock()
	x := g.rooms[ref.UserID]
	if x == nil || x.ref != ref {
		g.mu.Unlock()
		return ErrStale
	}
	x.denied = true
	if x.timer != nil {
		x.timer.Stop()
	}
	g.mu.Unlock()
	x.drain.Lock()
	defer x.drain.Unlock()
	g.mu.Lock()
	pending := make(map[uint64]closeFlow, len(x.flows))
	for id, close := range x.flows {
		pending[id] = close
	}
	g.mu.Unlock()
	for id, close := range pending {
		if ctx.Err() != nil {
			return ErrNotDrained
		}
		if close(ctx) == nil {
			g.mu.Lock()
			delete(x.flows, id)
			g.mu.Unlock()
		}
	}
	g.mu.Lock()
	empty := len(x.flows) == 0
	g.mu.Unlock()
	if !empty {
		return ErrNotDrained
	}
	return nil
}

func (g *Gates) Close(ctx context.Context) error {
	g.mu.Lock()
	g.closed = true
	refs := make([]Ref, 0, len(g.rooms))
	for _, x := range g.rooms {
		refs = append(refs, x.ref)
	}
	g.mu.Unlock()
	var err error
	for _, ref := range refs {
		if e := g.Drain(ctx, ref); e != nil {
			err = e
		}
	}
	return err
}
