package httpapi

import (
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/url"
	"salfetka/panel/internal/diagnostics"
	"salfetka/panel/internal/identity"
	"strings"
)

func (a *api) serveDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/diagnostics/invitations" {
		a.serveDiagnosticInvitation(w, r)
		return
	}
	if !method(w, r, http.MethodGet) {
		return
	}
	token := ""
	if cookie, err := r.Cookie(CookieName); err == nil {
		token = cookie.Value
	}
	session, err := a.identity.Authenticate(r.Context(), token)
	if fail(w, err) {
		return
	}
	roles := []identity.Role{identity.Owner, identity.Support, identity.Auditor, identity.InfrastructureOperator}
	if !role(w, session, roles...) {
		return
	}
	base := "/api/v1/diagnostics/testers"
	tester := ""
	if r.URL.Path != base {
		if !strings.HasPrefix(r.URL.Path, base+"/") {
			writeError(w, 404, "not_found")
			return
		}
		tester = strings.TrimPrefix(r.URL.Path, base+"/")
	}
	query, err := urlQuery(r)
	if err != nil || !diagnostics.ValidQuery(tester, query) {
		writeError(w, 400, "invalid_request")
		return
	}
	if a.config.Diagnostics == nil {
		writeError(w, 503, "diagnostics_not_configured")
		return
	}
	body, err := a.config.Diagnostics.Read(r.Context(), tester, query)
	if err != nil {
		if errors.Is(err, diagnostics.ErrNotFound) {
			writeError(w, 404, "not_found")
		} else {
			writeError(w, 503, "diagnostics_unavailable")
		}
		return
	}
	// Recheck revocation after the remote read, without holding DB locks over network IO.
	err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(pgx.Tx, identity.Session) error { return nil })
	if fail(w, err) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}
func urlQuery(r *http.Request) (string, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", err
	}
	for key, values := range q {
		if key != "before" || len(values) != 1 || values[0] == "" {
			return "", diagnostics.ErrInvalid
		}
	}
	if r.URL.RawPath != "" {
		return "", diagnostics.ErrInvalid
	}
	return q.Get("before"), nil
}
