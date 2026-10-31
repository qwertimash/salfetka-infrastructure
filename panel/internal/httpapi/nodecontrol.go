package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
)

// JSON receipts legitimately contain config:null on failure. Keep strict nested
// fields and duplicate-key rejection without weakening B1/B2 request decoding.
func decodeReceipt(w http.ResponseWriter, r *http.Request, receipt *nodewire.Receipt) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_request")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	defer r.Body.Close()
	if err != nil || !utf8.Valid(raw) {
		writeError(w, 400, "invalid_request")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err = uniqueJSON(decoder, 0); err != nil {
		writeError(w, 400, "invalid_request")
		return false
	}
	if _, err = decoder.Token(); err != io.EOF {
		writeError(w, 400, "invalid_request")
		return false
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(receipt) != nil {
		writeError(w, 400, "invalid_request")
		return false
	}
	return true
}
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("depth")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate")
			}
			seen[name] = true
			if err = uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object")
		}
	case '[':
		for d.More() {
			if err = uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array")
		}
	default:
		return errors.New("delimiter")
	}
	return nil
}
func (a *api) serveNodeControl(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == nodewire.DesiredPath || r.URL.Path == nodewire.ReceiptsPath {
		wanted := http.MethodGet
		if r.URL.Path == nodewire.ReceiptsPath {
			wanted = http.MethodPost
		}
		if !method(w, r, wanted) {
			return true
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			nodeFailure(w, nodes.ErrUnauthorized)
			return true
		}
		cert := r.TLS.PeerCertificates[0]
		if wanted == http.MethodGet {
			q, parseErr := url.ParseQuery(r.URL.RawQuery)
			if parseErr != nil || len(q) != 1 || len(q["node_id"]) != 1 || !identity.ValidID(q.Get("node_id")) {
				nodeFailure(w, nodes.ErrInvalid)
				return true
			}
			result, err := a.nodes.Desired(r.Context(), cert, q.Get("node_id"))
			if !nodeFailure(w, err) {
				writeJSON(w, 200, result)
			}
			return true
		}
		if r.URL.RawQuery != "" {
			nodeFailure(w, nodes.ErrInvalid)
			return true
		}
		var body nodewire.Receipt
		if !decodeReceipt(w, r, &body) {
			return true
		}
		result, replay, err := a.nodes.RecordReceipt(r.Context(), cert, body)
		if !nodeFailure(w, err) {
			if replay {
				w.Header().Set("Idempotent-Replayed", "true")
			}
			writeJSON(w, 200, result)
		}
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/")
	if len(parts) != 2 || !identity.ValidID(parts[0]) || (parts[1] != "config" && parts[1] != "control") {
		return false
	}
	id := parts[0]
	unsafe := parts[1] == "config"
	wanted := http.MethodGet
	if unsafe {
		wanted = http.MethodPost
	}
	if !method(w, r, wanted) {
		return true
	}
	if r.URL.RawQuery != "" {
		nodeFailure(w, nodes.ErrInvalid)
		return true
	}
	if unsafe && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
		writeError(w, 403, "origin_failed")
		return true
	}
	token := ""
	if cookie, err := r.Cookie(CookieName); err == nil {
		token = cookie.Value
	}
	session, err := a.identity.Authenticate(r.Context(), token)
	if fail(w, err) {
		return true
	}
	roles := []identity.Role{identity.Owner, identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor}
	if unsafe {
		roles = []identity.Role{identity.Owner, identity.InfrastructureOperator}
		if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
			fail(w, identity.ErrCSRF)
			return true
		}
	}
	if !role(w, session, roles...) {
		return true
	}
	if !unsafe {
		var result nodes.Control
		err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, _ identity.Session) error {
			var err error
			result, err = a.nodes.GetControlTx(r.Context(), tx, id)
			return err
		})
		if !nodeFailure(w, err) {
			writeJSON(w, 200, result)
		}
		return true
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 {
		nodeFailure(w, nodes.ErrInvalid)
		return true
	}
	revision, ok := revisionHeader(w, r)
	if !ok {
		return true
	}
	var body nodewire.AgentConfig
	if !decode(w, r, &body) {
		return true
	}
	var result json.RawMessage
	var replay bool
	err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		var err error
		result, replay, err = a.nodes.CreateCommandTx(r.Context(), tx, nodes.Mutation{ActorID: current.User.ID, Route: r.URL.Path, TargetID: id, Revision: revision, Key: r.Header.Get("Idempotency-Key")}, body)
		return err
	})
	if !nodeFailure(w, err) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 202, result)
	}
	return true
}
