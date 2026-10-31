package nodewire

import "time"

// Reports contain no wire credentials. Receipt is immutable; usage is a fresh,
// cumulative snapshot in one engine epoch, never a billable delta.
type VPNReport struct {
	Receipt     VPNReceipt `json:"receipt"`
	EngineEpoch string     `json:"engine_epoch"`
	Sequence    int64      `json:"sequence"`
	ObservedAt  time.Time  `json:"observed_at"`
	Usage       []VPNUsage `json:"usage"`
}
type VPNReportResponse struct {
	SchemaVersion int    `json:"schema_version"`
	NodeID        string `json:"node_id"`
	EngineEpoch   string `json:"engine_epoch"`
	Sequence      int64  `json:"sequence"`
	Status        string `json:"status"`
}
