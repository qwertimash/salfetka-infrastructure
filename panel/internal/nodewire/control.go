package nodewire

import "time"

const DesiredPath = "/api/v1/node/desired"
const ReceiptsPath = "/api/v1/node/receipts"

type AgentConfig struct {
	HeartbeatIntervalSeconds int `json:"heartbeat_interval_seconds"`
}
type Command struct {
	SchemaVersion  int         `json:"schema_version"`
	NodeID         string      `json:"node_id"`
	OperationID    string      `json:"operation_id"`
	AuthorityEpoch int64       `json:"authority_epoch"`
	Generation     int64       `json:"generation"`
	CreatedAt      time.Time   `json:"created_at"`
	DeadlineAt     time.Time   `json:"deadline_at"`
	Kind           string      `json:"kind"`
	PayloadSHA256  string      `json:"payload_sha256"`
	Payload        AgentConfig `json:"payload"`
}
type SignedCommand struct {
	Body      string `json:"body"`
	Signature string `json:"signature"`
}
type DesiredResponse struct {
	SchemaVersion int            `json:"schema_version"`
	NodeID        string         `json:"node_id"`
	Command       *SignedCommand `json:"command"`
}
type Receipt struct {
	SchemaVersion  int          `json:"schema_version"`
	NodeID         string       `json:"node_id"`
	OperationID    string       `json:"operation_id"`
	AuthorityEpoch int64        `json:"authority_epoch"`
	Generation     int64        `json:"generation"`
	CommandSHA256  string       `json:"command_sha256"`
	Status         string       `json:"status"`
	Config         *AgentConfig `json:"config"`
	ErrorCode      string       `json:"error_code,omitempty"`
	CompletedAt    time.Time    `json:"completed_at"`
}
type ReceiptResponse struct {
	SchemaVersion int    `json:"schema_version"`
	NodeID        string `json:"node_id"`
	OperationID   string `json:"operation_id"`
	Status        string `json:"status"`
}
