package nodeagent

import (
	"context"
	"net/http"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

func (a *Agent) FetchConnections(ctx context.Context) (nodewire.SignedConnectionsPlan, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out nodewire.SignedConnectionsPlan
	if a.closed || a.storagePoisoned || a.state.Enrollment == nil {
		return out, fault("node_vpn_runtime_unavailable")
	}
	request := struct {
		SchemaVersion int    `json:"schema_version"`
		NodeID        string `json:"node_id"`
	}{1, a.state.NodeID}
	if e := a.post(ctx, nodewire.ConnectionsDesiredPath, request, &out); e != nil {
		return out, e
	}
	p, e := nodecontrol.VerifyConnections(a.signer, out)
	if e != nil || p.NodeID != a.state.NodeID {
		return nodewire.SignedConnectionsPlan{}, fault("node_connections_response_invalid")
	}
	return out, nil
}
func (a *Agent) FetchConnectionVPN(ctx context.Context, c nodewire.ConnectionDeployment, epoch string) (nodewire.VPNDesired, error) {
	var out nodewire.VPNDesired
	client, err := a.connectionClient()
	if err != nil {
		return out, err
	}
	backend := ""
	if c.Configuration.Public.Template == "hysteria2" {
		backend = "hysteria2"
	}
	request := nodewire.VPNFetch{SchemaVersion: 1, NodeID: c.ID, InstallationID: c.InstallationID, EngineEpoch: epoch, Backend: backend, ProfileSHA256: connection.ProfileHash(c.Configuration.Public)}
	if e := a.requestUsing(ctx, http.MethodPost, nodewire.VPNDesiredPath, request, &out, client); e != nil {
		return out, e
	}
	if out.SchemaVersion != 1 || out.NodeID != c.ID || out.Policy == nil {
		return nodewire.VPNDesired{}, fault("node_vpn_response_invalid")
	}
	return out, nil
}
func (a *Agent) ReportConnectionVPN(ctx context.Context, r nodewire.VPNReport) error {
	client, err := a.connectionClient()
	if err != nil {
		return err
	}
	var out nodewire.VPNReportResponse
	if e := a.requestUsing(ctx, http.MethodPost, nodewire.VPNReceiptsPath, r, &out, client); e != nil {
		return e
	}
	if out.SchemaVersion != 1 || out.NodeID != r.Receipt.NodeID || out.EngineEpoch != r.EngineEpoch || out.Sequence != r.Sequence || out.Status != "recorded" {
		return fault("node_vpn_response_invalid")
	}
	return nil
}

func (a *Agent) ReportConnections(ctx context.Context, revision, sequence int64, states []nodewire.ConnectionState) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.storagePoisoned || a.state.Enrollment == nil {
		return fault("node_vpn_runtime_unavailable")
	}
	r := nodewire.ConnectionsReport{SchemaVersion: 1, NodeID: a.state.NodeID, BootID: a.bootID, Sequence: sequence, PlanRevision: revision, States: states}
	var response struct {
		Status string `json:"status"`
	}
	if e := a.post(ctx, nodewire.ConnectionsReceiptsPath, r, &response); e != nil {
		return e
	}
	if response.Status != "recorded" {
		return fault("node_connections_response_invalid")
	}
	return nil
}

// http.Client is concurrency safe; renewal replaces it while existing requests
// finish with their original mTLS identity. No mutable agent state escapes.
func (a *Agent) connectionClient() (*http.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.storagePoisoned || a.state.Enrollment == nil {
		return nil, fault("node_vpn_runtime_unavailable")
	}
	return a.client, nil
}
