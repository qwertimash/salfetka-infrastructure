package httpapi

import (
	"github.com/jackc/pgx/v5"
	"net/http"
	"regexp"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/identity"
)

var invitationKey = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

func (a *api) serveDiagnosticInvitation(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		writeError(w, 400, "invalid_request")
		return
	}
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin {
		writeError(w, 403, "origin_failed")
		return
	}
	token := ""
	if c, e := r.Cookie(CookieName); e == nil {
		token = c.Value
	}
	session, e := a.identity.Authenticate(r.Context(), token)
	if fail(w, e) || !role(w, session, identity.Owner) {
		return
	}
	if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
		fail(w, identity.ErrCSRF)
		return
	}
	var input struct {
		UserID string `json:"user_id"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !identity.ValidID(input.UserID) || len(r.Header.Values("Idempotency-Key")) != 1 || !invitationKey.MatchString(r.Header.Get("Idempotency-Key")) {
		writeError(w, 400, "invalid_request")
		return
	}
	if a.config.DiagnosticsInviter == nil {
		writeError(w, 503, "diagnostics_not_configured")
		return
	}
	var name string
	e = a.identity.WithAuthorizedSession(r.Context(), token, []identity.Role{identity.Owner}, func(tx pgx.Tx, _ identity.Session) error {
		d, e := a.access.DetailTx(r.Context(), tx, input.UserID)
		name = d.User.Name
		return e
	})
	if accessFailure(w, e) {
		return
	}
	result, e := a.config.DiagnosticsInviter.Invite(r.Context(), input.UserID, name, session.User.ID+":"+r.Header.Get("Idempotency-Key"))
	if e != nil {
		writeError(w, 503, "diagnostics_unavailable")
		return
	}
	// No DB transaction is held over network IO. A revoked owner cannot obtain the
	// returned code. The idempotent collector receipt survives an ambiguous reply.
	e = a.identity.WithAuthorizedSession(r.Context(), token, []identity.Role{identity.Owner}, func(tx pgx.Tx, current identity.Session) error {
		return audit.Append(r.Context(), tx, current.User.ID, "access.invite_created", input.UserID, "succeeded")
	})
	if !fail(w, e) {
		writeJSON(w, 200, result)
	}
}
