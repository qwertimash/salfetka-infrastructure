package nodeagent

import (
	"context"
	"salfetka/panel/internal/nodewire"
	"time"
)

// Renew changes only the certificate, never the key, CA, node or command state.
// The durable old serial is the retry identity; no new request nonce is needed.
func (a *Agent) Renew(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return fault("node_agent_closed")
	}
	if a.storagePoisoned {
		return fault("node_control_storage_failed")
	}
	if a.state.Enrollment == nil {
		return fault("node_not_enrolled")
	}
	key, err := parseKey(a.state.PrivateKeyPEM)
	if err != nil {
		return err
	}
	cert, err := verifyEnrollment(*a.state.Enrollment, a.state.NodeID, key)
	if err != nil {
		return err
	}
	now := a.now()
	high := cert.NotBefore
	if a.state.LastHeartbeat != nil {
		high = laterWall(high, a.state.LastHeartbeat.ReceivedAt)
	}
	if a.state.Control != nil {
		high = laterWall(high, a.state.Control.WallHighWater)
	}
	if !a.clockTrusted(high) {
		return fault("node_clock_untrusted")
	}
	if cert.NotAfter.Sub(now) > 8*time.Hour {
		return nil
	}
	request := nodewire.RenewalRequest{SchemaVersion: 1, NodeID: a.state.NodeID, PreviousSerial: a.state.Enrollment.Serial, CSRPEM: a.state.CSRPEM}
	var response nodewire.EnrollmentResponse
	if err = a.post(ctx, nodewire.RenewalPath, request, &response); err != nil {
		return err
	}
	if _, err = verifyEnrollment(response, a.state.NodeID, key); err != nil {
		return err
	}
	if response.AuthorityPEM != a.state.Enrollment.AuthorityPEM || response.Serial == a.state.Enrollment.Serial || !response.ExpiresAt.After(a.state.Enrollment.ExpiresAt) || response.ExpiresAt.After(now.Add(24*time.Hour+time.Minute)) {
		return fault("node_renewal_response_invalid")
	}
	next := a.state
	next.Enrollment = &response
	if err = a.saveControl(next); err != nil {
		return err
	}
	return a.makeClient()
}
