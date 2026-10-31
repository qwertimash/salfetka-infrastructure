package nodewire

const BypassSessionPath = "/api/v1/node/bypass/session"

// The machine endpoint is for an enrolled node. Client intent is verified by
// that node inside the protected carrier, never by trusting a supplied account.
type BypassRequest struct {
	PreviousEngineStopped bool   `json:"previous_engine_stopped"`
	SchemaVersion         int    `json:"schema_version"`
	NodeID                string `json:"node_id"`
	InstallationID        string `json:"installation_id"`
	EngineEpoch           string `json:"engine_epoch"`
	Nonce                 string `json:"nonce"`
	Operation             string `json:"operation"`
	CredentialID          string `json:"credential_id"`
	RequestID             string `json:"request_id"`
	UserID                string `json:"user_id"`
	Generation            int64  `json:"generation"`
	Revision              int64  `json:"revision"`
}

type BypassResponse struct {
	Code           string `json:"code,omitempty"`
	SchemaVersion  int    `json:"schema_version"`
	NodeID         string `json:"node_id"`
	InstallationID string `json:"installation_id"`
	EngineEpoch    string `json:"engine_epoch"`
	Nonce          string `json:"nonce"`
	Operation      string `json:"operation"`
	UserID         string `json:"user_id"`
	Generation     int64  `json:"generation"`
	Revision       int64  `json:"revision"`
	State          string `json:"state"`
	Reason         string `json:"reason"`
	RemainingMS    int64  `json:"remaining_ms"`
}
