package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/releases"
)

func builderFailure(w http.ResponseWriter, e error) bool {
	switch {
	case e == nil:
		return false
	case errors.Is(e, builder.ErrInvalid):
		writeError(w, 400, "invalid_request")
	case errors.Is(e, builder.ErrConflict):
		writeError(w, 409, "builder_conflict")
	case errors.Is(e, builder.ErrNotFound):
		writeError(w, 404, "not_found")
	case errors.Is(e, builder.ErrCapacity):
		writeError(w, 409, "builder_capacity")
	default:
		return releaseFailure(w, e)
	}
	return true
}
func (a *api) serveBuilder(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/builder")
	id := strings.TrimPrefix(path, "/")
	get := path == "" || identity.ValidID(id)
	if !get && path != "/save" && path != "/source" && path != "/stage" && path != "/preview" {
		writeError(w, 404, "not_found")
		return
	}
	verb := http.MethodPost
	if get {
		verb = http.MethodGet
	}
	if !method(w, r, verb) {
		return
	}
	if path != "" && r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_request")
		return
	}
	if !get && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
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
	roles := []identity.Role{identity.Owner, identity.InfrastructureOperator, identity.AccessOperator}
	if path == "/save" || path == "/source" {
		roles = []identity.Role{identity.Owner, identity.InfrastructureOperator}
	}
	if path == "/stage" || path == "/preview" {
		roles = []identity.Role{identity.Owner, identity.AccessOperator}
	}
	if !role(w, session, roles...) {
		return
	}
	if !get && (len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil) {
		fail(w, identity.ErrCSRF)
		return
	}
	store := builder.New(a.pool, a.config.Vault)
	var result any
	replay := false
	if get {
		if path == "" {
			if len(r.URL.Query()) > 1 || len(r.URL.Query()["after"]) > 1 {
				writeError(w, 400, "invalid_request")
				return
			}
			for k := range r.URL.Query() {
				if k != "after" {
					writeError(w, 400, "invalid_request")
					return
				}
			}
		}
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
			var e error
			if path == "" {
				result, e = store.ListTx(r.Context(), tx, r.URL.Query().Get("after"))
			} else {
				result, e = store.ReadTx(r.Context(), tx, id, 0)
			}
			return e
		})
	} else if path == "/save" {
		var input builder.Mutation
		if !decodeRelease(w, r, &input) {
			return
		}
		if len(r.Header.Values("Idempotency-Key")) != 1 {
			writeError(w, 400, "invalid_request")
			return
		}
		input.Key = r.Header.Get("Idempotency-Key")
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
			input.Actor = current.User.ID
			var e error
			result, replay, e = store.SaveTx(r.Context(), tx, input)
			return e
		})
	} else if path == "/source" {
		var input struct {
			ID        string `json:"id"`
			VersionID string `json:"version_id"`
		}
		if !decodeRelease(w, r, &input) {
			return
		}
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
			s, e := a.catalog.FrozenTx(r.Context(), tx, input.ID, input.VersionID, false, time.Now().UTC())
			if e != nil {
				return e
			}
			result, e = compiler.Outline(s, time.Now().UTC())
			return e
		})
	} else if path == "/stage" {
		var input struct {
			ID       string            `json:"id"`
			Revision int64             `json:"revision"`
			Mutation releases.Mutation `json:"mutation"`
		}
		if !decodeRelease(w, r, &input) {
			return
		}
		if len(r.Header.Values("Idempotency-Key")) != 1 {
			writeError(w, 400, "invalid_request")
			return
		}
		input.Mutation.Key = r.Header.Get("Idempotency-Key")
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
			input.Mutation.Actor = current.User.ID
			var e error
			result, replay, e = store.StageTx(r.Context(), tx, a.releases, input.ID, input.Revision, input.Mutation)
			return e
		})
	} else {
		var input struct {
			UserID    string `json:"user_id"`
			DeviceID  string `json:"device_id"`
			ReleaseID string `json:"release_id"`
		}
		if !decodeRelease(w, r, &input) {
			return
		}
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
			var e error
			result, e = a.releases.PreviewTx(r.Context(), tx, input.UserID, input.DeviceID, input.ReleaseID)
			return e
		})
	}
	if !builderFailure(w, e) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 200, result)
	}
}
