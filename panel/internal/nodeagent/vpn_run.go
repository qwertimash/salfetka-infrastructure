package nodeagent

import (
	"context"
	"crypto/ed25519"
	"salfetka/panel/internal/nodewire"
	"time"
)

type VPNController interface {
	Epoch() string
	Apply(nodewire.SignedVPNPolicy) (nodewire.VPNReceipt, error)
	Usage() ([]nodewire.VPNUsage, error)
	ObservedAt() (time.Time, error)
	Close()
}

// VPNBinding returns only public, validated enrollment/signing identity.
func (a *Agent) VPNBinding() (string, ed25519.PublicKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.storagePoisoned || a.state.Enrollment == nil || len(a.signer) != ed25519.PublicKeySize {
		return "", nil, fault("node_vpn_binding_unavailable")
	}
	return a.state.NodeID, append(ed25519.PublicKey(nil), a.signer...), nil
}
func (a *Agent) ReportVPN(ctx context.Context, r nodewire.VPNReport) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.storagePoisoned || a.state.Enrollment == nil || r.Receipt.NodeID != a.state.NodeID {
		return fault("node_vpn_runtime_unavailable")
	}
	var response nodewire.VPNReportResponse
	if err := a.post(ctx, nodewire.VPNReceiptsPath, r, &response); err != nil {
		return err
	}
	if response.SchemaVersion != 1 || response.NodeID != r.Receipt.NodeID || response.EngineEpoch != r.EngineEpoch || response.Sequence != r.Sequence || response.Status != "recorded" {
		return fault("node_vpn_response_invalid")
	}
	return nil
}
func terminalVPN(err error) bool {
	if err == nil {
		return false
	}
	switch err.Error() {
	case "node_authorization_rejected", "node_certificate_expired", "node_request_conflict", "node_not_enrolled", "node_agent_closed", "node_control_storage_failed", "node_clock_untrusted", "node_renewal_response_invalid", "node_vpn_runtime_unavailable":
		return true
	}
	return false
}

// RunVPN owns controller lifetime. VPN polling has an independent five-second
// cadence and bounded calls; control-plane loss cannot stop the engine's lease
// watchdog. Reports are cumulative snapshots, not retry-sensitive deltas.
func (a *Agent) RunVPN(ctx context.Context, installation string, c VPNController, report func(string)) error {
	return a.runVPN(ctx, installation, c, report, 5*time.Second)
}
func (a *Agent) runVPN(ctx context.Context, installation string, c VPNController, report func(string), interval time.Duration) error {
	defer c.Close()
	emit := func(code string) {
		if report != nil {
			report(code)
		}
	}
	var sequence int64
	var maintenance time.Time
	bounded := func(fn func(context.Context) error) error {
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return fn(call)
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		// Renewal goes first when due so a live node never keeps using an expired leaf.
		if time.Now().After(maintenance) {
			err := bounded(a.Renew)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				emit(err.Error())
				if terminalVPN(err) {
					return err
				}
			}
		}
		var desired nodewire.VPNDesired
		err := bounded(func(call context.Context) error {
			var e error
			backend := ""
			if typed, ok := c.(interface{ Backend() string }); ok {
				backend = typed.Backend()
			}
			profile := ""
			if typed, ok := c.(interface{ ProfileSHA256() string }); ok {
				profile = typed.ProfileSHA256()
			}
			desired, e = a.FetchVPN(call, installation, c.Epoch(), backend, profile)
			return e
		})
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			emit(err.Error())
			if terminalVPN(err) {
				return err
			}
		} else {
			receipt, e := c.Apply(*desired.Policy)
			if e != nil {
				code := vpnApplyCode(e)
				emit(code)
				return fault(code)
			}
			usage, e := c.Usage()
			if e != nil {
				emit("node_vpn_readback_failed")
				return fault("node_vpn_readback_failed")
			}
			sequence++
			if sequence > 9007199254740991 {
				return fault("node_sequence_exhausted")
			}
			observed, e := c.ObservedAt()
			if e != nil {
				code := vpnApplyCode(e)
				emit(code)
				return fault(code)
			}
			snapshot := nodewire.VPNReport{Receipt: receipt, EngineEpoch: c.Epoch(), Sequence: sequence, ObservedAt: observed, Usage: usage}
			e = bounded(func(call context.Context) error { return a.ReportVPN(call, snapshot) })
			if ctx.Err() != nil {
				return nil
			}
			if e != nil {
				emit(e.Error())
				if terminalVPN(e) {
					return e
				}
			} else {
				emit("node_vpn_synchronized")
			}
		}
		if time.Now().After(maintenance) {
			err = bounded(a.Heartbeat)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				emit(err.Error())
				if terminalVPN(err) {
					return err
				}
			} else {
				emit("node_heartbeat_recorded")
				err = bounded(a.SyncControl)
				if ctx.Err() != nil {
					return nil
				}
				if err != nil {
					emit(err.Error())
					if terminalVPN(err) {
						return err
					}
				}
			}
			maintenance = time.Now().Add(a.EffectiveInterval())
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// Only fixed local failure codes may reach logs; never forward arbitrary engine errors.
func vpnApplyCode(err error) string {
	switch err.Error() {
	case "vpn_runtime_unavailable", "vpn_signature_invalid", "vpn_target_mismatch", "vpn_clock_untrusted", "vpn_lease_expired", "vpn_generation_conflict", "vpn_storage_failed", "vpn_engine_clock_untrusted", "vpn_engine_grant_failed", "vpn_engine_readback_failed", "vpn_engine_activity_mismatch":
		return err.Error()
	default:
		return "node_vpn_apply_failed"
	}
}
