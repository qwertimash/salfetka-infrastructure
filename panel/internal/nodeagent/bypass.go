package nodeagent

import (
	"context"
	"net/http"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

// BypassSession shares the enrolled mTLS transport and validates a fresh response
// nonce. Callers retain their monotonic request start when applying RemainingMS.
func (a *Agent) BypassSession(ctx context.Context, q nodewire.BypassRequest) (nodewire.BypassResponse, error) {
	a.mu.Lock()
	var out nodewire.BypassResponse
	if a.closed || a.storagePoisoned || a.state.Enrollment == nil {
		a.mu.Unlock()
		return out, fault("node_bypass_unavailable")
	}
	q.SchemaVersion = 1
	q.NodeID = a.state.NodeID
	client := a.client
	if a.bypassSlots == nil {
		a.bypassSlots = make(chan struct{}, 16)
	}
	slots := a.bypassSlots
	a.mu.Unlock()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return out, ctx.Err()
	}
	var err error
	q.Nonce, err = database.NewID()
	if err != nil {
		return out, err
	}
	if err = a.requestUsing(ctx, http.MethodPost, nodewire.BypassSessionPath, q, &out, client); err != nil {
		return out, err
	}
	if out.SchemaVersion != 1 || out.NodeID != q.NodeID || out.InstallationID != q.InstallationID || out.EngineEpoch != q.EngineEpoch || out.Nonce != q.Nonce || out.Operation != q.Operation || out.RemainingMS < 0 || out.RemainingMS > 30000 {
		return nodewire.BypassResponse{}, fault("node_bypass_response_invalid")
	}
	return out, nil
}
