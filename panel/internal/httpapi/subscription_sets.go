package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/subscriptionsets"
)

var tokenPatternPublic = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func setFailure(w http.ResponseWriter, e error) bool {
	switch {
	case e == nil:
		return false
	case errors.Is(e, access.ErrLimit):
		writeError(w, 409, "device_limit")
	case errors.Is(e, subscriptionsets.ErrInvalid):
		writeError(w, 400, "invalid_request")
	case errors.Is(e, subscriptionsets.ErrNotFound):
		writeError(w, 404, "not_found")
	case errors.Is(e, subscriptionsets.ErrConflict):
		writeError(w, 409, "subscription_set_conflict")
	case errors.Is(e, subscriptionsets.ErrCapacity):
		writeError(w, 409, "subscription_set_capacity")
	default:
		return builderFailure(w, e)
	}
	return true
}

func (a *api) serveSubscriptionSets(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/subscription-sets")
	id := strings.TrimPrefix(path, "/")
	publicationID := strings.TrimPrefix(path, "/publications/")
	isPublication := strings.HasPrefix(path, "/publications/") && identity.ValidID(publicationID)
	get := path == "" || path == "/assignments" || path == "/targets" || identity.ValidID(id) || isPublication
	if !get && path != "/save" && path != "/assign" && path != "/publish" && path != "/link" && path != "/device-link" && path != "/invite" {
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
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || (!get && r.URL.RawQuery != "") {
		writeError(w, 400, "invalid_request")
		return
	}
	for k, values := range query {
		allowed := (path == "" && k == "after") || (path == "/targets" && (k == "publication_id" || k == "after")) || (path == "/assignments" && (k == "user_id" || k == "after")) || (identity.ValidID(id) && k == "revision")
		if !allowed || len(values) != 1 {
			writeError(w, 400, "invalid_request")
			return
		}
	}
	var revision int64
	if values, ok := query["revision"]; ok {
		revision, e = strconv.ParseInt(values[0], 10, 64)
		if e != nil || revision < 1 {
			writeError(w, 400, "invalid_request")
			return
		}
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
	if path == "/save" {
		roles = []identity.Role{identity.Owner, identity.InfrastructureOperator}
	}
	if path == "/targets" || path == "/assign" || path == "/assignments" || path == "/publish" || path == "/link" || path == "/device-link" || path == "/invite" {
		roles = []identity.Role{identity.Owner, identity.AccessOperator}
	}
	if !role(w, session, roles...) {
		return
	}
	if !get && (len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil) {
		fail(w, identity.ErrCSRF)
		return
	}
	if a.config.Vault == nil {
		writeError(w, 503, "key_unavailable")
		return
	}
	store := subscriptionsets.Store{Builder: builder.New(a.pool, a.config.Vault)}
	var result any
	replay := false
	if get {
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
			var e error
			switch path {
			case "":
				result, e = store.ListTx(r.Context(), tx, query.Get("after"))
			case "/targets":
				result, e = store.TargetsTx(r.Context(), tx, query.Get("publication_id"), query.Get("after"))
			case "/assignments":
				result, e = store.AssignmentsTx(r.Context(), tx, query.Get("user_id"), query.Get("after"))
			default:
				if isPublication {
					result, e = store.PublicationTx(r.Context(), tx, publicationID)
				} else {
					result, e = store.ReadTx(r.Context(), tx, id, revision)
				}
			}
			return e
		})
	} else if path == "/invite" {
		var input struct {
			AssignmentID string `json:"assignment_id"`
		}
		if !decodeRelease(w, r, &input) {
			return
		}
		if len(r.Header.Values("Idempotency-Key")) != 1 {
			writeError(w, 400, "invalid_request")
			return
		}
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
			invite, again, err := access.New(a.pool, a.config.Vault).MintInviteTx(r.Context(), tx, current.User.ID, input.AssignmentID, r.Header.Get("Idempotency-Key"))
			if err != nil {
				return err
			}
			replay = again
			result = map[string]any{"url": a.config.SubscriptionOrigin + "/i/" + invite.Token, "expires_at": invite.ExpiresAt}
			return nil
		})
	} else if path == "/link" || path == "/device-link" {
		var input struct {
			AssignmentID string `json:"assignment_id"`
			DeviceID     string `json:"device_id,omitempty"`
		}
		if !decodeRelease(w, r, &input) {
			return
		}
		if path == "/link" && input.DeviceID != "" {
			writeError(w, 400, "invalid_request")
			return
		}
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
			var link string
			var err error
			if path == "/link" {
				link, err = store.AssignmentLinkTx(r.Context(), tx, current.User.ID, input.AssignmentID)
			} else {
				link, err = store.DeviceLinkTx(r.Context(), tx, a.releases, current.User.ID, input.AssignmentID, input.DeviceID)
			}
			if err != nil {
				return err
			}
			prefix := "/a/"
			if path == "/device-link" {
				prefix = "/s/"
			}
			result = map[string]string{"url": a.config.SubscriptionOrigin + prefix + link}
			return nil
		})
	} else {
		if len(r.Header.Values("Idempotency-Key")) != 1 {
			writeError(w, 400, "invalid_request")
			return
		}
		if path == "/save" {
			var m subscriptionsets.Save
			if !decodeRelease(w, r, &m) {
				return
			}
			m.Key = r.Header.Get("Idempotency-Key")
			e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
				m.Actor = current.User.ID
				var e error
				result, replay, e = store.SaveTx(r.Context(), tx, m)
				return e
			})
		} else if path == "/publish" {
			var m subscriptionsets.Publish
			if !decodeRelease(w, r, &m) {
				return
			}
			m.Key = r.Header.Get("Idempotency-Key")
			e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
				m.Actor = current.User.ID
				var err error
				result, replay, err = store.PublishTx(r.Context(), tx, m)
				return err
			})
		} else {
			var m subscriptionsets.Assign
			if !decodeRelease(w, r, &m) {
				return
			}
			m.Key = r.Header.Get("Idempotency-Key")
			e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
				m.Actor = current.User.ID
				var e error
				result, replay, e = store.AssignTx(r.Context(), tx, m)
				return e
			})
		}
	}
	if !setFailure(w, e) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 200, result)
	}
}

func (a *api) serveAssignmentResolve(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, 404, "not_found")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/a/")
	if !tokenPatternPublic.MatchString(token) {
		writeError(w, 404, "not_found")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"type": "salfetka-assignment", "version": 1, "requires_device_proof": true})
		return
	}
	select {
	case a.subscriptionSlots <- struct{}{}:
		defer func() { <-a.subscriptionSlots }()
	default:
		writeError(w, 429, "busy")
		return
	}
	var proof subscriptionsets.DeviceProof
	if !decodeRelease(w, r, &proof) {
		return
	}
	store := subscriptionsets.Store{Builder: builder.New(a.pool, a.config.Vault)}
	token, e := store.Resolve(r.Context(), a.releases, token, proof)
	if e != nil {
		if errors.Is(e, releases.ErrDenied) {
			writeError(w, 404, "not_found")
		} else {
			writeError(w, 503, "subscription_unavailable")
		}
		return
	}
	writeJSON(w, 200, map[string]string{"url": a.config.SubscriptionOrigin + "/s/" + token})
}
