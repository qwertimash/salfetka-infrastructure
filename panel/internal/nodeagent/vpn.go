package nodeagent

import (
	"context"
	"salfetka/panel/internal/nodewire"
)

// FetchVPN uses the enrolled mTLS identity. Applying/persisting the returned policy
// belongs to nodevpn.Controller, which independently verifies its signature/epoch.
func (a *Agent) FetchVPN(ctx context.Context, installationID, engineEpoch string, backends ...string) (nodewire.VPNDesired, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out nodewire.VPNDesired
	if a.closed || a.storagePoisoned {
		return out, fault("node_vpn_runtime_unavailable")
	}
	if a.state.Enrollment == nil {
		return out, fault("node_not_enrolled")
	}
	backend := ""
	if len(backends) > 2 {
		return out, fault("node_vpn_backend_invalid")
	}
	if len(backends) >= 1 {
		backend = backends[0]
	}
	if !nodewire.ValidBackend(backend) {
		return out, fault("node_vpn_backend_invalid")
	}
	profile := ""
	if len(backends) == 2 {
		profile = backends[1]
	}
	request := nodewire.VPNFetch{Backend: backend, ProfileSHA256: profile, SchemaVersion: 1, NodeID: a.state.NodeID, InstallationID: installationID, EngineEpoch: engineEpoch}
	if err := a.post(ctx, nodewire.VPNDesiredPath, request, &out); err != nil {
		return out, err
	}
	if out.SchemaVersion != 1 || out.NodeID != a.state.NodeID || out.Policy == nil {
		return nodewire.VPNDesired{}, fault("node_vpn_response_invalid")
	}
	return out, nil
}
