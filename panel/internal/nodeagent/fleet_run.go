package nodeagent

import (
	"context"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodevpn"
	"salfetka/panel/internal/nodewire"
	"time"
)

// RunFleet maintains one enrolled identity and independent policy/counter scopes.
// Network I/O never holds the fleet lock or blocks its lease watchdog.
func (a *Agent) RunFleet(ctx context.Context, f *nodevpn.Fleet, report func(string)) error {
	defer f.Close()
	a.mu.Lock()
	a.cfg.ManagedConnections = true
	a.mu.Unlock()
	emit := func(code string) {
		if report != nil {
			report(code)
		}
	}
	bounded := func(fn func(context.Context) error) error {
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return fn(call)
	}
	var maintenance time.Time
	var sequence int64
	sequences := map[string]int64{}
	for ctx.Err() == nil {
		if time.Now().After(maintenance) {
			for _, fn := range []func(context.Context) error{a.Renew, a.Heartbeat, a.SyncControl} {
				if e := bounded(fn); e != nil {
					emit(e.Error())
					if terminalVPN(e) {
						return e
					}
				}
			}
			maintenance = time.Now().Add(a.EffectiveInterval())
		}
		var signed nodewire.SignedConnectionsPlan
		e := bounded(func(call context.Context) error { var e error; signed, e = a.FetchConnections(call); return e })
		if e != nil {
			emit(e.Error())
			if terminalVPN(e) {
				return e
			}
		} else {
			_, pub, e := a.VPNBinding()
			if e != nil {
				return e
			}
			plan, e := nodecontrol.VerifyConnections(pub, signed)
			if e != nil {
				return fault("node_connections_response_invalid")
			}
			states, e := f.Apply(signed)
			if e != nil {
				return e
			}
			// Four independent, bounded workers prevent one slow connection from
			// serializing every policy renewal. Even 32 timed-out connections
			// finish a cycle well inside the two-minute policy lease.
			type result struct {
				id, code string
				failed   bool
			}
			bindings := f.Bindings()
			results := make(chan result, len(bindings))
			slots := make(chan struct{}, 4)
			activeEpochs := map[string]bool{}
			for _, b := range bindings {
				activeEpochs[b.Epoch] = true
				sequences[b.Epoch]++
				seq := sequences[b.Epoch]
				go func(b nodevpn.FleetBinding, seq int64) {
					select {
					case slots <- struct{}{}:
					case <-ctx.Done():
						results <- result{id: b.Deployment.ID}
						return
					}
					defer func() { <-slots }()
					done := result{id: b.Deployment.ID}
					defer func() { results <- done }()
					var desired nodewire.VPNDesired
					err := bounded(func(call context.Context) error {
						var err error
						desired, err = a.FetchConnectionVPN(call, b.Deployment, b.Epoch)
						return err
					})
					if err != nil {
						done.code = err.Error()
						if terminalVPN(err) {
							f.Drop(b.Deployment.ID, b.Epoch)
							done.failed = true
						}
						return
					}
					var snapshot nodewire.VPNReport
					err = f.WithConnection(b.Deployment.ID, b.Epoch, func(c nodevpn.FleetController) error {
						receipt, err := c.Apply(*desired.Policy)
						if err != nil {
							return err
						}
						usage, err := c.Usage()
						if err != nil {
							return err
						}
						at, err := c.ObservedAt()
						if err != nil {
							return err
						}
						snapshot = nodewire.VPNReport{Receipt: receipt, EngineEpoch: b.Epoch, Sequence: seq, ObservedAt: at, Usage: usage}
						return nil
					})
					if err != nil {
						f.Drop(b.Deployment.ID, b.Epoch)
						done.failed = true
						done.code = "connection_policy_failed"
						return
					}
					if err = bounded(func(call context.Context) error { return a.ReportConnectionVPN(call, snapshot) }); err != nil {
						done.code = err.Error()
					}
				}(b, seq)
			}
			for range bindings {
				r := <-results
				if r.code != "" {
					emit(r.code)
				}
				if r.failed {
					for i := range states {
						if states[i].ID == r.id {
							states[i].State = "failed"
							states[i].ErrorCode = "connection_policy_failed"
						}
					}
				}
			}
			for epoch := range sequences {
				if !activeEpochs[epoch] {
					delete(sequences, epoch)
				}
			}

			sequence++
			if sequence > 9007199254740991 {
				return fault("node_sequence_exhausted")
			}
			if e = bounded(func(call context.Context) error { return a.ReportConnections(call, plan.Revision, sequence, states) }); e != nil {
				emit(e.Error())
			}
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}
