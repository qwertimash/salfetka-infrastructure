package nodewire

import "time"

const VPNDesiredPath = "/api/v1/node/vpn/desired"
const VPNReceiptsPath = "/api/v1/node/vpn/receipts"

// VPNPolicy is a complete desired set, not a patch. Missing grants are denied.
// InstallationID binds an explicitly owned engine installation; counter epoch is
// separate and changes whenever the actual engine process is recreated.
type VPNPolicy struct {
	Backend        string     `json:"backend,omitempty"`
	ProfileSHA256  string     `json:"profile_sha256,omitempty"`
	SchemaVersion  int        `json:"schema_version"`
	NodeID         string     `json:"node_id"`
	InstallationID string     `json:"installation_id"`
	EngineEpoch    string     `json:"engine_epoch"`
	AuthorityEpoch int64      `json:"authority_epoch"`
	Generation     int64      `json:"generation"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Grants         []VPNGrant `json:"grants"`
}
type VPNGrant struct {
	AccountID  string    `json:"account_id,omitempty"`
	RoomID     string    `json:"room_id,omitempty"`
	ID         string    `json:"id"`
	Generation int64     `json:"generation"`
	Enabled    bool      `json:"enabled"`
	Credential string    `json:"credential,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}
type SignedVPNPolicy struct {
	Body      string `json:"body"`
	Signature string `json:"signature"`
}
type VPNDesired struct {
	SchemaVersion int              `json:"schema_version"`
	NodeID        string           `json:"node_id"`
	Policy        *SignedVPNPolicy `json:"policy"`
}
type VPNUsage struct {
	Ready         *bool  `json:"ready,omitempty"`
	GrantID       string `json:"grant_id"`
	InstanceEpoch string `json:"instance_epoch"`
	Generation    int64  `json:"generation"`
	Active        bool   `json:"active"`
	Uplink        *int64 `json:"uplink"`
	Downlink      *int64 `json:"downlink"`
}
type VPNReceipt struct {
	SchemaVersion  int        `json:"schema_version"`
	NodeID         string     `json:"node_id"`
	InstallationID string     `json:"installation_id"`
	Generation     int64      `json:"generation"`
	PolicySHA256   string     `json:"policy_sha256"`
	Status         string     `json:"status"`
	ErrorCode      string     `json:"error_code,omitempty"`
	Usage          []VPNUsage `json:"usage"`
	CompletedAt    time.Time  `json:"completed_at"`
}

// VPNFetch requests a policy bound to this fresh engine epoch over mTLS.
type VPNFetch struct {
	Backend        string `json:"backend,omitempty"`
	ProfileSHA256  string `json:"profile_sha256,omitempty"`
	SchemaVersion  int    `json:"schema_version"`
	NodeID         string `json:"node_id"`
	InstallationID string `json:"installation_id"`
	EngineEpoch    string `json:"engine_epoch"`
}
