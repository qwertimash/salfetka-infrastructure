// Package nodewire defines the bounded B3.1 machine API. A recorded heartbeat is
// evidence of control-channel contact only, never an engine or VPN acknowledgement.
package nodewire

import "time"

const SchemaVersion = 1
const EnrollmentPath = "/api/v1/node/enroll"
const HeartbeatPath = "/api/v1/node/heartbeat"
const IdentityURIPrefix = "spiffe://salfetka/node/"

type EnrollmentRequest struct {
	SchemaVersion int    `json:"schema_version"`
	NodeID        string `json:"node_id"`
	Token         string `json:"token"`
	RequestID     string `json:"request_id"`
	CSRPEM        string `json:"csr_pem"`
}
type EnrollmentResponse struct {
	SchemaVersion  int       `json:"schema_version"`
	NodeID         string    `json:"node_id"`
	CertificatePEM string    `json:"certificate_pem"`
	AuthorityPEM   string    `json:"authority_pem"`
	Serial         string    `json:"serial"`
	ExpiresAt      time.Time `json:"expires_at"`
}
type HeartbeatRequest struct {
	Site          *SiteStatus `json:"site,omitempty"`
	SchemaVersion int         `json:"schema_version"`
	NodeID        string      `json:"node_id"`
	BootID        string      `json:"boot_id"`
	Sequence      int64       `json:"sequence"`
	Version       string      `json:"version"`
	Platform      string      `json:"platform"`
	Arch          string      `json:"arch"`
	Capabilities  []string    `json:"capabilities"`
}

// Only public certificate material crosses the control channel.
type SiteStatus struct {
	ExpiresAt      time.Time `json:"expires_at"`
	Domain         string    `json:"domain"`
	CertificatePEM string    `json:"certificate_pem,omitempty"`
	State          string    `json:"state"`
}

const SiteInfoPath = "/api/v1/node/site-info"

type SiteInfo struct {
	SchemaVersion int    `json:"schema_version"`
	NodeID        string `json:"node_id"`
	Domain        string `json:"domain"`
	Address       string `json:"address"`
}
type HeartbeatResponse struct {
	SchemaVersion int       `json:"schema_version"`
	NodeID        string    `json:"node_id"`
	Sequence      int64     `json:"sequence"`
	ReceivedAt    time.Time `json:"received_at"`
	Status        string    `json:"status"`
	EngineState   string    `json:"engine_state"`
}
