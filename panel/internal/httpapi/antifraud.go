package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/antifraud"
	"salfetka/panel/internal/identity"
)

func (a *api) serveAntifraud(w http.ResponseWriter, r *http.Request) {
	mutation := r.URL.Path == "/api/v1/antifraud/release"
	if !mutation && r.URL.Path != "/api/v1/antifraud/accounts" {
		writeError(w, 404, "not_found")
		return
	}
	want := http.MethodGet
	if mutation {
		want = http.MethodPost
	}
	if !method(w, r, want) {
		return
	}
	if mutation && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
		writeError(w, 403, "origin_failed")
		return
	}
	token := ""
	if c, err := r.Cookie(CookieName); err == nil {
		token = c.Value
	}
	session, err := a.identity.Authenticate(r.Context(), token)
	if fail(w, err) {
		return
	}
	roles := []identity.Role{identity.Owner, identity.Support, identity.Auditor}
	if mutation {
		roles = []identity.Role{identity.Owner}
		if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
			fail(w, identity.ErrCSRF)
			return
		}
	}
	if !role(w, session, roles...) {
		return
	}
	if a.config.Antifraud == nil {
		writeError(w, 503, "antifraud_not_configured")
		return
	}
	if mutation {
		if r.URL.RawQuery != "" {
			writeError(w, 400, "invalid_request")
			return
		}
		var body struct {
			AccountID  string `json:"account_id"`
			IncidentID int64  `json:"incident_id"`
		}
		if !decode(w, r, &body) {
			return
		}
		if !antifraud.ValidID(body.AccountID) || body.IncidentID <= 0 {
			writeError(w, 400, "invalid_request")
			return
		}
		var released bool
		// Keep the owner's authorization locked through the bounded remote action.
		// The controller records the authoritative audit atomically with the release.
		// On a lost reply retrying this exact incident is safe, never a newer incident.
		err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(_ pgx.Tx, current identity.Session) error {
			var e error
			released, e = a.config.Antifraud.Release(r.Context(), body.AccountID, body.IncidentID, current.User.ID)
			return e
		})
		if antifraudFailure(w, err) {
			return
		}
		writeJSON(w, 200, map[string]bool{"released": released})
		return
	}
	// ParseQuery rejects malformed escapes instead of treating them as no filter.
	q, err := parseAntifraudQuery(r)
	if err != nil {
		writeError(w, 400, "invalid_request")
		return
	}
	page, err := a.config.Antifraud.Read(r.Context(), q)
	if antifraudFailure(w, err) {
		return
	}
	err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(pgx.Tx, identity.Session) error { return nil })
	if fail(w, err) {
		return
	}
	writeJSON(w, 200, page)
}
func parseAntifraudQuery(r *http.Request) (string, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || r.URL.RawPath != "" {
		return "", antifraud.ErrInvalid
	}
	for k, v := range q {
		if k != "after" || len(v) != 1 || !antifraud.ValidID(v[0]) {
			return "", antifraud.ErrInvalid
		}
	}
	return q.Get("after"), nil
}
func antifraudFailure(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, antifraud.ErrUnavailable):
		writeError(w, 503, "antifraud_unavailable")
	case errors.Is(err, antifraud.ErrConflict):
		writeError(w, 409, "antifraud_conflict")
	case errors.Is(err, antifraud.ErrInvalid):
		writeError(w, 400, "invalid_request")
	default:
		return fail(w, err)
	}
	return true
}
