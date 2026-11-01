package httpapi

import (
	"net/http"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
)

func (a *api) serveManagedNode(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != nodewire.ConnectionsDesiredPath && r.URL.Path != nodewire.ConnectionsReceiptsPath && r.URL.Path != nodewire.SiteInfoPath {
		return false
	}
	if !method(w, r, http.MethodPost) {
		return true
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		nodeFailure(w, nodes.ErrInvalid)
		return true
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		nodeFailure(w, nodes.ErrUnauthorized)
		return true
	}
	if r.URL.Path == nodewire.ConnectionsReceiptsPath {
		var report nodewire.ConnectionsReport
		if !decode(w, r, &report) {
			return true
		}
		if !nodeFailure(w, a.nodes.RecordConnections(r.Context(), r.TLS.PeerCertificates[0], report)) {
			writeJSON(w, 200, map[string]string{"status": "recorded"})
		}
		return true
	}
	var in struct {
		SchemaVersion int    `json:"schema_version"`
		NodeID        string `json:"node_id"`
	}
	if !decode(w, r, &in) {
		return true
	}
	if in.SchemaVersion != 1 {
		nodeFailure(w, nodes.ErrInvalid)
		return true
	}
	if r.URL.Path == nodewire.SiteInfoPath {
		out, e := a.nodes.SiteInfo(r.Context(), r.TLS.PeerCertificates[0], in.NodeID)
		if !nodeFailure(w, e) {
			writeJSON(w, 200, out)
		}
		return true
	}
	out, e := a.nodes.ConnectionsDesired(r.Context(), r.TLS.PeerCertificates[0], in.NodeID)
	if !nodeFailure(w, e) {
		writeJSON(w, 200, out)
	}
	return true
}
