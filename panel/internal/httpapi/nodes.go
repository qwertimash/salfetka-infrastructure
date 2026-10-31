package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
)

func nodeFailure(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var fieldError nodes.ServerFieldError
	if errors.As(err, &fieldError) {
		writeError(w, http.StatusBadRequest, string(fieldError))
		return true
	}
	status, code := 0, ""
	switch {
	case errors.Is(err, nodes.ErrVPNCapacity):
		status, code = 503, "node_vpn_capacity"
	case errors.Is(err, nodes.ErrInvalid):
		status, code = 400, "invalid_request"
	case errors.Is(err, nodes.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(err, nodes.ErrConflict):
		status, code = 409, "conflict"
	case errors.Is(err, nodes.ErrRevision):
		status, code = 412, "revision_conflict"
	case errors.Is(err, nodes.ErrProof):
		status, code = 400, "node_proof_invalid"
	case errors.Is(err, nodes.ErrEnrollment):
		status, code = 403, "node_enrollment_invalid"
	case errors.Is(err, nodes.ErrExpired):
		status, code = 403, "node_enrollment_expired"
	case errors.Is(err, nodes.ErrUnauthorized):
		status, code = 401, "node_unauthorized"
	case errors.Is(err, nodes.ErrKey), errors.Is(err, nodes.ErrAuthority):
		status, code = 503, "node_configuration_unavailable"
	default:
		return fail(w, err)
	}
	writeError(w, status, code)
	return true
}
func (a *api) serveNodes(w http.ResponseWriter, r *http.Request) {
	if a.serveBypassSession(w, r) {
		return
	}
	if a.serveNodeVPN(w, r) {
		return
	}
	if a.serveNodeControl(w, r) {
		return
	}
	if r.URL.Path == nodewire.EnrollmentPath || r.URL.Path == nodewire.HeartbeatPath || r.URL.Path == nodewire.RenewalPath {
		if !method(w, r, http.MethodPost) {
			return
		}
		if r.URL.RawQuery != "" {
			nodeFailure(w, nodes.ErrInvalid)
			return
		}
		if r.URL.Path == nodewire.EnrollmentPath {
			var body nodewire.EnrollmentRequest
			if !decode(w, r, &body) {
				return
			}
			result, replay, err := a.nodes.Enroll(r.Context(), body)
			if !nodeFailure(w, err) {
				if replay {
					w.Header().Set("Idempotent-Replayed", "true")
				}
				writeJSON(w, 200, result)
			}
			return
		}
		// Browser cookies, unverified peer certificates and proxy headers confer no
		// machine authority. TLS verifies the chain, then the store checks current DB state.
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			nodeFailure(w, nodes.ErrUnauthorized)
			return
		}
		if r.URL.Path == nodewire.RenewalPath {
			var body nodewire.RenewalRequest
			if !decode(w, r, &body) {
				return
			}
			result, replay, err := a.nodes.Renew(r.Context(), r.TLS.PeerCertificates[0], body)
			if !nodeFailure(w, err) {
				if replay {
					w.Header().Set("Idempotent-Replayed", "true")
				}
				writeJSON(w, 200, result)
			}
			return
		}
		var body nodewire.HeartbeatRequest
		if !decode(w, r, &body) {
			return
		}
		result, replay, err := a.nodes.Heartbeat(r.Context(), r.TLS.PeerCertificates[0], body)
		if !nodeFailure(w, err) {
			if replay {
				w.Header().Set("Idempotent-Replayed", "true")
			}
			writeJSON(w, 200, result)
		}
		return
	}
	route := ""
	id := ""
	allowed := []string{http.MethodPost}
	if r.URL.Path == "/api/v1/nodes" {
		route = "nodes"
		allowed = []string{http.MethodGet, http.MethodPost}
	} else if strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") {
		p := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/")
		if len(p) > 0 && identity.ValidID(p[0]) {
			id = p[0]
			if len(p) == 1 {
				route = "detail"
				allowed = []string{http.MethodGet}
			} else if len(p) == 2 && (p[1] == "enrollment" || p[1] == "revoke") {
				route = p[1]
			}
		}
	}
	if route == "" {
		writeError(w, 404, "not_found")
		return
	}
	if !method(w, r, allowed...) {
		return
	}
	unsafe := r.Method == http.MethodPost
	if unsafe && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
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
	roles := []identity.Role{identity.Owner, identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor}
	if unsafe {
		roles = []identity.Role{identity.Owner, identity.InfrastructureOperator}
		if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
			fail(w, identity.ErrCSRF)
			return
		}
	}
	if !role(w, session, roles...) {
		return
	}
	if !unsafe {
		var result any
		if route == "nodes" {
			limit, cursor, ok := pagination(w, r)
			if !ok {
				return
			}
			err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
				items, e := a.nodes.ListTx(r.Context(), tx, limit, cursor)
				next := ""
				if len(items) == limit {
					next = items[len(items)-1].ID
				}
				result = map[string]any{"items": items, "next_cursor": next}
				return e
			})
		} else {
			if r.URL.RawQuery != "" {
				nodeFailure(w, nodes.ErrInvalid)
				return
			}
			err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
				n, e := a.nodes.GetTx(r.Context(), tx, id)
				result = n
				return e
			})
		}
		if !nodeFailure(w, err) {
			if n, ok := result.(nodes.Node); ok {
				w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Revision, 10)))
			}
			writeJSON(w, 200, result)
		}
		return
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 || r.URL.RawQuery != "" {
		nodeFailure(w, nodes.ErrInvalid)
		return
	}
	m := nodes.Mutation{Route: r.URL.Path, TargetID: id, Key: r.Header.Get("Idempotency-Key")}
	if id != "" {
		var ok bool
		m.Revision, ok = revisionHeader(w, r)
		if !ok {
			return
		}
	}
	var name string
	if route == "nodes" {
		var body struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &body) {
			return
		}
		name = body.Name
	} else {
		var body struct{}
		if !decode(w, r, &body) {
			return
		}
	}
	var result any
	var replay bool
	err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		m.ActorID = current.User.ID
		var e error
		switch route {
		case "nodes":
			result, replay, e = a.nodes.CreateTx(r.Context(), tx, m, name)
		case "enrollment":
			result, replay, e = a.nodes.EnrollmentTx(r.Context(), tx, m)
		default:
			result, replay, e = a.nodes.RevokeTx(r.Context(), tx, m)
		}
		return e
	})
	if !nodeFailure(w, err) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		switch n := result.(type) {
		case nodes.Node:
			w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Revision, 10)))
		case nodes.EnrollmentCreated:
			w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Node.Revision, 10)))
		}
		status := 200
		if route == "nodes" || route == "enrollment" {
			status = 201
		}
		writeJSON(w, status, result)
	}
}
