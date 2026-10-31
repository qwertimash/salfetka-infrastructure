package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/secrets"
)

func sourceFailure(w http.ResponseWriter, e error) bool {
	if e == nil {
		return false
	}
	var parse importer.Error
	switch {
	case errors.Is(e, catalog.ErrNotFound):
		writeError(w, 404, "not_found")
	case errors.Is(e, catalog.ErrRevision):
		writeError(w, 412, "revision_conflict")
	case errors.Is(e, catalog.ErrConflict):
		writeError(w, 409, "conflict")
	case errors.Is(e, catalog.ErrCapacity):
		writeError(w, 409, "source_capacity")
	case errors.Is(e, catalog.ErrExpired):
		writeError(w, 410, "source_draft_expired")
	case errors.Is(e, secrets.ErrUnavailable):
		writeError(w, 503, "key_unavailable")
	case errors.As(e, &parse):
		code := "source_invalid"
		if parse == "source_json" || parse == "source_duplicate_key" || parse == "source_depth" {
			code = "source_invalid_json"
		}
		if parse == "source_size" || parse == "source_count" {
			code = "source_size"
		}
		if parse == "source_unknown_field" || parse == "source_unknown_parameter" || parse == "source_protocol" || parse == "source_engine" || parse == "source_transport" || parse == "source_bypass_carrier" {
			code = "source_unsupported"
		}
		if strings.HasPrefix(string(parse), "source_routing") || strings.HasPrefix(string(parse), "source_rule") || parse == "source_location_member" || parse == "source_location_mode" || parse == "source_location_dns" {
			code = "source_routing_invalid"
		}
		if parse == "source_expired" {
			code = "source_expired"
		} else if parse == "source_tls_required" {
			code = "source_tls_required"
		} else if parse == "source_address_denied" || parse == "source_url" {
			code = "source_address_denied"
		} else if parse == "source_fetch_failed" || parse == "source_http_status" || parse == "source_dns_failed" {
			code = "source_fetch_failed"
		}
		writeError(w, 422, code)
	case errors.Is(e, catalog.ErrInvalid):
		writeError(w, 400, "invalid_request")
	default:
		return fail(w, e)
	}
	return true
}
func (a *api) serveSources(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimPrefix(r.URL.Path, "/api/v1/sources")
	historyID := ""
	parts := strings.Split(strings.TrimPrefix(route, "/"), "/")
	if len(parts) == 2 && parts[1] == "versions" && identity.ValidID(parts[0]) {
		historyID = parts[0]
	}
	if route != "" && route != "/preview" && route != "/mutate" && historyID == "" {
		writeError(w, 404, "not_found")
		return
	}
	verb := http.MethodPost
	if route == "" || historyID != "" {
		verb = http.MethodGet
	}
	if !method(w, r, verb) {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_request")
		return
	}
	write := verb == http.MethodPost
	if write && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
		writeError(w, 403, "origin_failed")
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
	if write {
		roles = []identity.Role{identity.Owner, identity.InfrastructureOperator}
		if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
			fail(w, identity.ErrCSRF)
			return
		}
	}
	if !role(w, session, roles...) {
		return
	}
	if !write {
		if historyID != "" {
			var items []catalog.Version
			e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
				var e error
				items, e = a.catalog.VersionsTx(r.Context(), tx, historyID)
				return e
			})
			if !sourceFailure(w, e) {
				writeJSON(w, 200, map[string]any{"items": items})
			}
			return
		}
		var items []catalog.Source
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
			var e error
			items, e = a.catalog.ListTx(r.Context(), tx)
			return e
		})
		if !sourceFailure(w, e) {
			writeJSON(w, 200, map[string]any{"items": items})
		}
		return
	}
	if route == "/preview" {
		// Bounded per-process work: four concurrent imports, no queued secret bodies.
		select {
		case a.importSlots <- struct{}{}:
			defer func() { <-a.importSlots }()
		default:
			writeError(w, 429, "rate_limited")
			return
		}
		var input catalog.Input
		if !decodeLimit(w, r, &input, importer.MaxBytes*6+4096) {
			return
		}
		p, e := a.catalog.Prepare(r.Context(), input)
		if sourceFailure(w, e) {
			return
		}
		var draft catalog.Draft
		// Recheck authorization after network/parse work, so demotion or logout while
		// fetching cannot persist a draft. Fetching does not hold a user/DB lock.
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
			var e error
			draft, e = a.catalog.DraftTx(r.Context(), tx, current.User.ID, p)
			return e
		})
		if !sourceFailure(w, e) {
			writeJSON(w, 201, draft)
		}
		return
	}
	var body struct {
		Operation string `json:"operation"`
		ID        string `json:"id"`
		Revision  int64  `json:"revision"`
		DraftID   string `json:"draft_id"`
		VersionID string `json:"version_id"`
		Paused    bool   `json:"paused"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 {
		writeError(w, 400, "invalid_request")
		return
	}
	m := catalog.Mutation{Operation: body.Operation, ID: body.ID, Revision: body.Revision, DraftID: body.DraftID, VersionID: body.VersionID, Paused: body.Paused, Key: r.Header.Get("Idempotency-Key")}
	var out catalog.Source
	var replay bool
	e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		m.Actor = current.User.ID
		var e error
		out, replay, e = a.catalog.MutateTx(r.Context(), tx, m)
		return e
	})
	if !sourceFailure(w, e) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 200, out)
	}
}
