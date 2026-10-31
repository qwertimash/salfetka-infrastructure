package httpapi

import (
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"strings"
)

func (a *api) serveVPNExport(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/access/users/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/api/v1/access/users/") || len(parts) != 4 || !identity.ValidID(parts[0]) || parts[1] != "devices" || !identity.ValidID(parts[2]) || parts[3] != "vpn-config" {
		return false
	}
	if !method(w, r, http.MethodPost) {
		return true
	}
	if r.URL.RawQuery != "" || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin {
		writeError(w, 403, "origin_failed")
		return true
	}
	token := ""
	if cookie, e := r.Cookie(CookieName); e == nil {
		token = cookie.Value
	}
	session, err := a.identity.Authenticate(r.Context(), token)
	if fail(w, err) {
		return true
	}
	roles := []identity.Role{identity.Owner, identity.AccessOperator}
	if !role(w, session, roles...) {
		return true
	}
	if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
		fail(w, identity.ErrCSRF)
		return true
	}
	var body struct {
		NodeID string `json:"node_id"`
	}
	if !decode(w, r, &body) {
		return true
	}
	if !identity.ValidID(body.NodeID) {
		writeError(w, 400, "invalid_request")
		return true
	}
	var config any
	err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		// Lock node before user, matching issuance ordering.
		state, e := a.nodes.VPNStatusTx(r.Context(), tx, body.NodeID)
		if e != nil {
			return e
		}
		if state.Installation == nil || !state.Installation.Enabled || state.Installation.Endpoint == nil || state.State != "applied" {
			return nodes.ErrConflict
		}
		endpoint := state.Installation.Endpoint
		if !endpoint.Valid() {
			return nodes.ErrInvalid
		}
		grant, key, e := a.access.VPNCredentialTx(r.Context(), tx, parts[0], parts[2], body.NodeID, state.Installation.GroupID, endpoint.Backend)
		if e != nil {
			return e
		}
		observed := false
		for _, u := range state.Observed.Usage {
			if u.GrantID == grant && u.Active && (u.Ready == nil || *u.Ready) {
				observed = true
			}
		}
		if !observed {
			return nodes.ErrConflict
		}
		raw, e := nodes.PersonalClientConfig(r.Context(), tx, *endpoint, key, state.Installation.InstallationID, parts[0], false)
		if e != nil {
			return nodes.ErrConflict
		}
		var native map[string]any
		if json.Unmarshal(raw, &native) != nil {
			return nodes.ErrInvalid
		}
		if endpoint.Engine() == "xray" {
			native["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}}
		}
		config = native

		return audit.Append(r.Context(), tx, current.User.ID, "access.vpn_config_exported", parts[0], "succeeded")
	})
	if err != nil {
		if errors.Is(err, access.ErrConflict) || errors.Is(err, access.ErrNotFound) || errors.Is(err, access.ErrKey) || errors.Is(err, access.ErrInvalid) {
			accessFailure(w, err)
		} else {
			nodeFailure(w, err)
		}
		return true
	}
	w.Header().Set("Content-Disposition", `attachment; filename="salfetka-trial-connection.json"`)
	writeJSON(w, 200, config)
	return true
}
