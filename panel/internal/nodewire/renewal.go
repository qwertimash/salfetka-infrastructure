package nodewire

const RenewalPath = "/api/v1/node/renew"

type RenewalRequest struct {
	SchemaVersion  int    `json:"schema_version"`
	NodeID         string `json:"node_id"`
	PreviousSerial string `json:"previous_serial"`
	CSRPEM         string `json:"csr_pem"`
}
