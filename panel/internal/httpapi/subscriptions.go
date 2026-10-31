package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"mime"
	"net/http"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/releases"
	"strconv"
	"strings"
)

func releaseFailure(w http.ResponseWriter, e error) bool {
	if e == nil {
		return false
	}
	switch {
	case errors.Is(e, access.ErrKey):
		writeError(w, 503, "key_unavailable")
	case errors.Is(e, releases.ErrInvalid), errors.Is(e, access.ErrInvalid), errors.Is(e, compiler.ErrInvalid):
		writeError(w, 400, "invalid_request")
	case errors.Is(e, releases.ErrDenied):
		writeError(w, 403, "subscription_denied")
	case errors.Is(e, releases.ErrUnavailable):
		writeError(w, 409, "subscription_unavailable")
	case errors.Is(e, releases.ErrCapacity):
		writeError(w, 409, "release_capacity")
	case errors.Is(e, releases.ErrConflict), errors.Is(e, access.ErrConflict), errors.Is(e, access.ErrRevision):
		writeError(w, 409, "release_conflict")
	case errors.Is(e, compiler.ErrPolicyConflict):
		writeError(w, 422, "release_policy_conflict")
	case errors.Is(e, compiler.ErrMapping):
		writeError(w, 422, "release_mapping_required")
	case errors.Is(e, compiler.ErrCapability):
		writeError(w, 422, "release_capability")
	case errors.Is(e, nodes.ErrNotFound), errors.Is(e, nodes.ErrConflict), errors.Is(e, access.ErrNotFound):
		writeError(w, 409, "subscription_unavailable")
	default:
		return sourceFailure(w, e)
	}
	return true
}

// Negotiation never strips unsupported locations or downgrades v2 routing.
func manifestMedia(header string, version int) (string, bool) {
	const vendor = "application/vnd.salfetka.subscription+json"
	if header == "" {
		return vendor, true
	}
	chosen := ""
	chosenQ := 0.0
	chosenRank := -1
	for _, candidate := range []string{vendor, "application/json"} {
		best := -1
		quality := 0.0
		for _, item := range strings.Split(header, ",") {
			media, params, e := mime.ParseMediaType(strings.TrimSpace(item))
			if e != nil {
				continue
			}
			rank := -1
			if media == candidate {
				rank = 2
			} else if media == "application/*" {
				rank = 1
			} else if media == "*/*" {
				rank = 0
			}
			if rank < 0 {
				continue
			}
			q := 1.0
			valid := true
			for key, value := range params {
				switch key {
				case "q":
					q, e = strconv.ParseFloat(value, 64)
					if e != nil || q < 0 || q > 1 {
						valid = false
					}
				case "version":
					if value != strconv.Itoa(version) {
						valid = false
					} else {
						rank++
					}
				default:
					valid = false
				}
			}
			if valid && (rank > best || rank == best && q > quality) {
				best, quality = rank, q
			}
		}
		if quality > chosenQ || quality > 0 && quality == chosenQ && best > chosenRank {
			chosen, chosenQ, chosenRank = candidate, quality, best
		}
	}
	return chosen, chosenQ > 0
}
func (a *api) serveSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Vary", "Accept")
	if !method(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	// Empty error responses keep HEAD semantics identical even for malformed tokens.
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		w.WriteHeader(404)
		return
	}
	select {
	case a.subscriptionSlots <- struct{}{}:
		defer func() { <-a.subscriptionSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/s/")
	artifact, e := a.releases.Delivery(r.Context(), token)
	if e != nil {
		if errors.Is(e, releases.ErrDenied) {
			w.WriteHeader(404)
		} else {
			w.Header().Set("Retry-After", "15")
			w.WriteHeader(503)
		}
		return
	}
	defer clear(artifact.Body)
	version := 1
	v, e := importer.Decode(artifact.Body)
	if e != nil {
		w.WriteHeader(503)
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		w.WriteHeader(503)
		return
	}
	if fmtVersion := m["version"]; fmtVersion != nil && fmtVersion.(json.Number).String() == "2" {
		version = 2
	}
	media, accepted := manifestMedia(r.Header.Get("Accept"), version)
	if !accepted {
		w.WriteHeader(406)
		return
	}
	w.Header().Set("Content-Type", media+"; version="+strconv.Itoa(version))
	w.Header().Set("Content-Disposition", `attachment; filename="salfetka-subscription.json"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(artifact.Body)))
	w.WriteHeader(200)
	if r.Method == http.MethodGet {
		w.Write(artifact.Body)
	}
}
func (a *api) serveSubscriptions(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/subscriptions")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	read := len(parts) == 2 && identity.ValidID(parts[0]) && identity.ValidID(parts[1])
	if path != "/mutate" && path != "/link" && !read {
		writeError(w, 404, "not_found")
		return
	}
	verb := http.MethodPost
	if read {
		verb = http.MethodGet
	}
	if !method(w, r, verb) {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_request")
		return
	}
	if !read && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
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
	roles := []identity.Role{identity.Owner, identity.AccessOperator, identity.Support, identity.Auditor}
	if !read {
		roles = []identity.Role{identity.Owner, identity.AccessOperator}
		if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
			fail(w, identity.ErrCSRF)
			return
		}
	}
	if !role(w, session, roles...) {
		return
	}
	if read {
		var out releases.Detail
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
			var e error
			out, e = a.releases.DetailTx(r.Context(), tx, parts[0], parts[1])
			return e
		})
		if !releaseFailure(w, e) {
			writeJSON(w, 200, out)
		}
		return
	}
	if path == "/link" {
		var in struct {
			UserID   string `json:"user_id"`
			DeviceID string `json:"device_id"`
		}
		if !decode(w, r, &in) {
			return
		}
		var secret string
		e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
			var e error
			secret, e = a.releases.LinkTx(r.Context(), tx, current.User.ID, in.UserID, in.DeviceID)
			return e
		})
		if !releaseFailure(w, e) {
			writeJSON(w, 200, map[string]string{"url": a.config.SubscriptionOrigin + "/s/" + secret})
		}
		return
	}
	var in releases.Mutation
	if !decodeRelease(w, r, &in) {
		return
	}
	if in.DraftID != "" || in.DraftRevision != 0 {
		writeError(w, 400, "invalid_request")
		return
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 {
		writeError(w, 400, "invalid_request")
		return
	}
	in.Key = r.Header.Get("Idempotency-Key")
	var out releases.Detail
	var replay bool
	e = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		in.Actor = current.User.ID
		var e error
		out, replay, e = a.releases.MutateTx(r.Context(), tx, in)
		return e
	})
	if !releaseFailure(w, e) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 200, out)
	}
}

func decodeRelease(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		writeError(w, 415, "invalid_request")
		return false
	}
	defer r.Body.Close()
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if e != nil {
		writeError(w, 400, "invalid_request")
		return false
	}
	v, e := importer.Decode(b)
	m, ok := v.(map[string]any)
	if e != nil || !ok {
		writeError(w, 400, "invalid_request")
		return false
	}
	for _, v := range m {
		if v == nil {
			writeError(w, 400, "invalid_request")
			return false
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		writeError(w, 400, "invalid_request")
		return false
	}
	return true
}
