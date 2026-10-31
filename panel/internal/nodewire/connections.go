package nodewire

import (
	"salfetka/panel/internal/connection"
	"time"
)

const ConnectionsDesiredPath = "/api/v1/node/connections/desired"

type ConnectionDeployment struct {
	ID                  string                   `json:"id"`
	InstallationID      string                   `json:"installation_id"`
	Revision            int64                    `json:"revision"`
	Enabled             bool                     `json:"enabled"`
	ConfigurationSHA256 string                   `json:"configuration_sha256"`
	Configuration       connection.Configuration `json:"configuration"`
}
type ConnectionsPlan struct {
	SchemaVersion int                    `json:"schema_version"`
	NodeID        string                 `json:"node_id"`
	Revision      int64                  `json:"revision"`
	IssuedAt      time.Time              `json:"issued_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Connections   []ConnectionDeployment `json:"connections"`
}
type SignedConnectionsPlan struct {
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

const ConnectionsReceiptsPath = "/api/v1/node/connections/receipts"

type ConnectionState struct {
	ID        string `json:"id"`
	Revision  int64  `json:"revision"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code,omitempty"`
}
type ConnectionsReport struct {
	SchemaVersion int               `json:"schema_version"`
	NodeID        string            `json:"node_id"`
	BootID        string            `json:"boot_id"`
	Sequence      int64             `json:"sequence"`
	PlanRevision  int64             `json:"plan_revision"`
	States        []ConnectionState `json:"states"`
}
