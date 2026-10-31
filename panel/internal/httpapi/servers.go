package httpapi

import (
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/url"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"strconv"
	"strings"
)

func (a *api) serveServers(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/servers")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	connection := len(parts) == 2 && (identity.ValidID(parts[0]) || parts[0] == "unassigned") && parts[1] == "connections"
	history := len(parts) == 2 && identity.ValidID(parts[0]) && parts[1] == "config-history"
	if path != "" && !connection && !history {
		writeError(w, 404, "not_found")
		return
	}
	if !method(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	write := r.Method == http.MethodPost
	if write && (history || (connection && parts[0] == "unassigned")) {
		writeError(w, 405, "method_not_allowed")
		return
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || r.URL.RawPath != "" || (write && r.URL.RawQuery != "") {
		writeError(w, 400, "invalid_request")
		return
	}
	for k, v := range query {
		if len(v) != 1 || (k != "after" || history) && (k != "before" || !history) {
			writeError(w, 400, "invalid_request")
			return
		}
	}
	before := int64(0)
	if history && query.Get("before") != "" {
		before, e = strconv.ParseInt(query.Get("before"), 10, 64)
		if e != nil || before < 1 {
			writeError(w, 400, "invalid_request")
			return
		}
	}
	token := ""
	if c, e := r.Cookie(CookieName); e == nil {
		token = c.Value
	}
	session, e := a.identity.Authenticate(r.Context(), token)
	if fail(w, e) {
		return
	}
	roles := []identity.Role{identity.Owner, identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor}
	if write || history {
		roles = []identity.Role{identity.Owner, identity.InfrastructureOperator}
	}
	if !role(w, session, roles...) {
		return
	}
	if write && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
		writeError(w, 403, "origin_failed")
		return
	}
	if write && (len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil) {
		fail(w, identity.ErrCSRF)
		return
	}
	var name, address, domain string
	if write {
		var input struct {
			Name    string  `json:"name"`
			Address *string `json:"address"`
			Domain  *string `json:"domain"`
		}
		if !decode(w, r, &input) {
			return
		}
		name = input.Name
		if input.Address != nil {
			address = *input.Address
		}
		if input.Domain != nil {
			domain = *input.Domain
		}
		if (connection && (input.Address != nil || input.Domain != nil)) || (!connection && (input.Address == nil || input.Domain == nil)) {
			writeError(w, 400, "invalid_request")
			return
		}
		if len(r.Header.Values("Idempotency-Key")) != 1 {
			writeError(w, 400, "invalid_request")
			return
		}
	}
	var result any
	replay := false
	e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		var err error
		if !write {
			if history {
				var versions []nodes.VPNConfigVersion
				versions, err = a.nodes.VPNHistoryTx(r.Context(), tx, parts[0], before)
				result = map[string]any{"items": versions}
			}
			if connection {
				result, err = a.nodes.ServerConnectionsTx(r.Context(), tx, parts[0], query.Get("after"))
			}
			if path == "" {
				result, err = a.nodes.ServersTx(r.Context(), tx, query.Get("after"))
			}
			return err
		}
		m := nodes.Mutation{ActorID: current.User.ID, Route: r.URL.Path, Key: r.Header.Get("Idempotency-Key")}
		if connection {
			result, replay, err = a.nodes.CreateServerConnectionTx(r.Context(), tx, m, parts[0], name)
		} else {
			result, replay, err = a.nodes.CreateServerTx(r.Context(), tx, m, name, address, domain)
		}
		return err
	})
	if !nodeFailure(w, e) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 200, result)
	}
}
