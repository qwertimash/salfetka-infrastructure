package httpapi

import (
	"net/http"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
)

func (a *api) serveBypassSession(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != nodewire.BypassSessionPath {
		return false
	}
	if !method(w, r, http.MethodPost) {
		return true
	}
	if r.URL.RawQuery != "" {
		nodeFailure(w, nodes.ErrInvalid)
		return true
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		nodeFailure(w, nodes.ErrUnauthorized)
		return true
	}
	var q nodewire.BypassRequest
	if !decode(w, r, &q) {
		return true
	}
	out, err := a.nodes.BypassSession(r.Context(), r.TLS.PeerCertificates[0], q)
	if !nodeFailure(w, err) {
		writeJSON(w, 200, out)
	}
	return true
}
