package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/identity"
)

func accessFailure(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	status, code := 0, ""
	switch {
	case errors.Is(err, access.ErrInvalid):
		status, code = 400, "invalid_request"
	case errors.Is(err, access.ErrNotFound):
		status, code = 404, "not_found"
	case errors.Is(err, access.ErrRevision):
		status, code = 412, "revision_conflict"
	case errors.Is(err, access.ErrConflict):
		status, code = 409, "conflict"
	case errors.Is(err, access.ErrTerminal):
		status, code = 409, "terminal_entitlement"
	case errors.Is(err, access.ErrLimit):
		status, code = 409, "device_limit"
	case errors.Is(err, access.ErrProof):
		status, code = 409, "proof_invalid"
	case errors.Is(err, access.ErrBound):
		status, code = 409, "device_bound"
	case errors.Is(err, access.ErrChallengeExpired):
		status, code = 409, "challenge_expired"
	case errors.Is(err, access.ErrChallengeUsed):
		status, code = 409, "challenge_used"
	case errors.Is(err, access.ErrKey):
		status, code = 503, "key_unavailable"
	default:
		return fail(w, err)
	}
	writeError(w, status, code)
	return true
}
func revisionHeader(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if len(r.Header.Values("If-Match")) != 1 {
		accessFailure(w, access.ErrInvalid)
		return 0, false
	}
	n, err := strconv.Unquote(r.Header.Get("If-Match"))
	if err != nil {
		accessFailure(w, access.ErrInvalid)
		return 0, false
	}
	v, err := strconv.ParseInt(n, 10, 64)
	if err != nil || v < 1 || strconv.FormatInt(v, 10) != n {
		accessFailure(w, access.ErrInvalid)
		return 0, false
	}
	return v, true
}
func (a *api) serveAccess(w http.ResponseWriter, r *http.Request) {
	if a.serveVPNExport(w, r) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/access/"), "/")
	route := ""
	uid := ""
	target := ""
	methods := []string{http.MethodPost}
	switch {
	case len(parts) == 1 && parts[0] == "groups":
		route = "groups"
		methods = []string{http.MethodGet}
	case len(parts) == 1 && parts[0] == "users":
		route = "users"
		methods = []string{http.MethodGet, http.MethodPost}
	case len(parts) >= 2 && parts[0] == "users" && identity.ValidID(parts[1]):
		uid = parts[1]
		switch {
		case len(parts) == 2:
			route = "detail"
			methods = []string{http.MethodGet}
		case len(parts) == 3 && (parts[2] == "state" || parts[2] == "entitlement" || parts[2] == "blocks"):
			route = parts[2]
		case len(parts) == 4 && parts[2] == "devices" && (parts[3] == "challenges" || parts[3] == "register"):
			route = parts[3]
		case len(parts) == 5 && parts[2] == "blocks" && identity.ValidID(parts[3]) && parts[4] == "clear":
			route = "clear"
			target = parts[3]
		case len(parts) == 5 && parts[2] == "devices" && identity.ValidID(parts[3]) && (parts[4] == "revoke" || parts[4] == "rotate"):
			route = parts[4]
			target = parts[3]
		}
	}
	if route == "" {
		writeError(w, 404, "not_found")
		return
	}
	if !method(w, r, methods...) {
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
	roles := []identity.Role{identity.Owner, identity.AccessOperator, identity.Support, identity.Auditor}
	if unsafe {
		roles = []identity.Role{identity.Owner, identity.AccessOperator}
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
		if route == "users" {
			limit, cursor, ok := pagination(w, r)
			if !ok {
				return
			}
			err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
				items, e := a.access.ListTx(r.Context(), tx, limit, cursor)
				next := ""
				if len(items) == limit {
					next = items[len(items)-1].ID
				}
				result = map[string]any{"items": items, "next_cursor": next}
				return e
			})
		} else {
			if r.URL.RawQuery != "" {
				accessFailure(w, access.ErrInvalid)
				return
			}
			err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
				if route == "groups" {
					items, e := a.access.GroupsTx(r.Context(), tx)
					result = map[string]any{"items": items}
					return e
				}
				detail, e := a.access.DetailTx(r.Context(), tx, uid)
				result = detail
				return e
			})
		}
		if !accessFailure(w, err) {
			if d, ok := result.(access.Detail); ok {
				w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(d.User.Revision, 10)))
			}
			writeJSON(w, 200, result)
		}
		return
	}
	if r.URL.RawQuery != "" || len(r.Header.Values("Idempotency-Key")) != 1 {
		accessFailure(w, access.ErrInvalid)
		return
	}
	mutation := access.Mutation{Route: r.URL.Path, TargetID: uid, Key: r.Header.Get("Idempotency-Key")}
	if uid != "" {
		var ok bool
		mutation.Revision, ok = revisionHeader(w, r)
		if !ok {
			return
		}
	}
	var invoke func(pgx.Tx, identity.Session) (any, bool, error)
	switch route {
	case "users":
		var body struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &body) {
			return
		}
		invoke = func(tx pgx.Tx, current identity.Session) (any, bool, error) {
			mutation.ActorID = current.User.ID
			return a.access.CreateTx(r.Context(), tx, mutation, body.Name)
		}
	case "state":
		var body struct {
			State string `json:"state"`
		}
		if !decode(w, r, &body) {
			return
		}
		invoke = func(tx pgx.Tx, current identity.Session) (any, bool, error) {
			mutation.ActorID = current.User.ID
			return a.access.StateTx(r.Context(), tx, mutation, body.State)
		}
	case "entitlement":
		var body access.EntitlementChange
		if !decode(w, r, &body) {
			return
		}
		invoke = func(tx pgx.Tx, current identity.Session) (any, bool, error) {
			mutation.ActorID = current.User.ID
			return a.access.EntitlementTx(r.Context(), tx, mutation, body)
		}
	case "blocks":
		var body access.BlockChange
		if !decode(w, r, &body) {
			return
		}
		invoke = func(tx pgx.Tx, current identity.Session) (any, bool, error) {
			mutation.ActorID = current.User.ID
			return a.access.BlockTx(r.Context(), tx, mutation, body)
		}
	case "challenges":
		var body struct {
			PublicKey string `json:"public_key"`
		}
		if !decode(w, r, &body) {
			return
		}
		invoke = func(tx pgx.Tx, current identity.Session) (any, bool, error) {
			mutation.ActorID = current.User.ID
			return a.access.ChallengeTx(r.Context(), tx, mutation, body.PublicKey)
		}
	case "register":
		var body access.Register
		if !decode(w, r, &body) {
			return
		}
		invoke = func(tx pgx.Tx, current identity.Session) (any, bool, error) {
			mutation.ActorID = current.User.ID
			return a.access.RegisterTx(r.Context(), tx, mutation, body)
		}
	default:
		var body struct{}
		if !decode(w, r, &body) {
			return
		}
		invoke = func(tx pgx.Tx, current identity.Session) (any, bool, error) {
			mutation.ActorID = current.User.ID
			if route == "clear" {
				return a.access.ClearBlockTx(r.Context(), tx, mutation, target)
			}
			return a.access.DeviceTx(r.Context(), tx, mutation, target, route)
		}
	}
	var result any
	var replay bool
	err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		var e error
		result, replay, e = invoke(tx, current)
		return e
	})
	if !accessFailure(w, err) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		switch d := result.(type) {
		case access.Detail:
			w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(d.User.Revision, 10)))
		case access.Challenge:
			w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(d.UserRevision, 10)))
		}
		status := 200
		if route == "users" || route == "challenges" {
			status = 201
		}
		writeJSON(w, status, result)
	}
}
