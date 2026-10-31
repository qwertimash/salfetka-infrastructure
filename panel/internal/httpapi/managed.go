package httpapi

import (
	"github.com/jackc/pgx/v5"
	"net/http"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"strings"
)

func (a *api) serveManaged(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/managed/"), "/")
	installInfo := len(parts) == 1 && parts[0] == "install-info"
	templates := len(parts) == 1 && parts[0] == "templates"
	server := len(parts) >= 2 && parts[0] == "servers" && identity.ValidID(parts[1])
	register := server && len(parts) == 3 && parts[2] == "node"
	detail := server && len(parts) == 2
	batch := len(parts) == 3 && parts[0] == "nodes" && identity.ValidID(parts[1]) && parts[2] == "connections"
	edit := len(parts) == 2 && parts[0] == "connections" && identity.ValidID(parts[1])
	history := len(parts) == 3 && parts[0] == "connections" && identity.ValidID(parts[1]) && parts[2] == "history"
	if !installInfo && !templates && !register && !detail && !batch && !edit && !history {
		writeError(w, 404, "not_found")
		return
	}
	write := register || batch || edit
	allowed := http.MethodGet
	if write {
		allowed = http.MethodPost
	}
	if !method(w, r, allowed) {
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		writeError(w, 400, "invalid_request")
		return
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
	if write || history || installInfo {
		roles = []identity.Role{identity.Owner, identity.InfrastructureOperator}
	}
	if !role(w, session, roles...) {
		return
	}
	if write {
		if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin {
			writeError(w, 403, "origin_failed")
			return
		}
		if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
			fail(w, identity.ErrCSRF)
			return
		}
		if len(r.Header.Values("Idempotency-Key")) != 1 {
			writeError(w, 400, "invalid_request")
			return
		}
	}
	var revision int64
	var requests struct {
		Connections []nodes.ManagedRequest `json:"connections"`
	}
	var update nodes.ManagedUpdate
	if batch || edit {
		var ok bool
		revision, ok = revisionHeader(w, r)
		if !ok {
			return
		}
	}
	if batch && !decodeLimit(w, r, &requests, 4*1024*1024) {
		return
	}
	if edit && !decodeLimit(w, r, &update, 256*1024) {
		return
	}
	if register {
		var empty struct{}
		if !decode(w, r, &empty) {
			return
		}
	}
	var out any
	var replay bool
	e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		var e error
		switch {
		case installInfo:
			out, e = a.installInfo()
		case templates:
			out = map[string]any{"items": connection.Templates()}
		case detail:
			out, e = a.nodes.ManagedServerTx(r.Context(), tx, parts[1])
		case history:
			out, e = a.nodes.ManagedHistoryTx(r.Context(), tx, parts[1])
		default:
			m := nodes.Mutation{ActorID: current.User.ID, Route: r.URL.Path, Key: r.Header.Get("Idempotency-Key"), Revision: revision}
			if register {
				out, replay, e = a.nodes.RegisterServerNodeTx(r.Context(), tx, m, parts[1])
			} else {
				m.TargetID = parts[1]
				if batch {
					out, replay, e = a.nodes.CreateManagedConnectionsTx(r.Context(), tx, m, requests.Connections)
				} else {
					out, replay, e = a.nodes.UpdateManagedConnectionTx(r.Context(), tx, m, update)
				}
			}
		}
		return e
	})
	if !nodeFailure(w, e) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 200, out)
	}
}
