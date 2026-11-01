package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"mime"
	"net/http"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodewire"
	"strings"
	"unicode/utf8"
)

func (a *api) serveNodeVPN(w http.ResponseWriter, r *http.Request) bool {
	machine := r.URL.Path == nodewire.VPNDesiredPath || r.URL.Path == nodewire.VPNReceiptsPath
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/")
	admin := strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") && len(parts) == 2 && identity.ValidID(parts[0]) && parts[1] == "vpn"
	if !machine && !admin {
		return false
	}
	if !(admin && r.Method == http.MethodGet) && !method(w, r, http.MethodPost) {
		return true
	}
	if r.URL.RawQuery != "" {
		nodeFailure(w, nodes.ErrInvalid)
		return true
	}
	if machine {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			nodeFailure(w, nodes.ErrUnauthorized)
			return true
		}
		if r.URL.Path == nodewire.VPNReceiptsPath {
			var body nodewire.VPNReport
			if !decodeNodeDocument(w, r, &body) {
				return true
			}
			result, replay, err := a.nodes.RecordVPN(r.Context(), r.TLS.PeerCertificates[0], body)
			if !nodeFailure(w, err) {
				if replay {
					w.Header().Set("Idempotent-Replayed", "true")
				}
				writeJSON(w, 200, result)
			}
			return true
		}
		var input struct {
			Backend        *string `json:"backend"`
			ProfileSHA256  *string `json:"profile_sha256"`
			SchemaVersion  int     `json:"schema_version"`
			NodeID         string  `json:"node_id"`
			InstallationID string  `json:"installation_id"`
			EngineEpoch    string  `json:"engine_epoch"`
		}
		if !decode(w, r, &input) {
			return true
		}
		backend := ""
		if input.Backend != nil {
			backend = *input.Backend
		}
		profile := ""
		if input.ProfileSHA256 != nil {
			profile = *input.ProfileSHA256
		}
		body := nodes.VPNFetch{Backend: backend, ProfileSHA256: profile, SchemaVersion: input.SchemaVersion, NodeID: input.NodeID, InstallationID: input.InstallationID, EngineEpoch: input.EngineEpoch}
		result, replay, err := a.nodes.VPNDesired(r.Context(), r.TLS.PeerCertificates[0], body)
		if !nodeFailure(w, err) {
			if replay {
				w.Header().Set("Idempotent-Replayed", "true")
			}
			writeJSON(w, 200, result)
		}
		return true
	}
	if admin && r.Method == http.MethodGet {
		token := ""
		if cookie, e := r.Cookie(CookieName); e == nil {
			token = cookie.Value
		}
		var result nodes.VPNStatus
		err := a.identity.WithAuthorizedSession(r.Context(), token, []identity.Role{identity.Owner, identity.InfrastructureOperator, identity.AccessOperator, identity.Support, identity.Auditor}, func(tx pgx.Tx, _ identity.Session) error {
			var e error
			result, e = a.nodes.VPNStatusTx(r.Context(), tx, parts[0])
			return e
		})
		if !nodeFailure(w, err) {
			writeJSON(w, 200, result)
		}
		return true
	}
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin {
		writeError(w, 403, "origin_failed")
		return true
	}
	token := ""
	if cookie, e := r.Cookie(CookieName); e == nil {
		token = cookie.Value
	}
	session, err := a.identity.Authenticate(r.Context(), token)
	if fail(w, err) {
		return true
	}
	roles := []identity.Role{identity.Owner, identity.InfrastructureOperator}
	if len(r.Header.Values("X-CSRF-Token")) != 1 || identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token")) != nil {
		fail(w, identity.ErrCSRF)
		return true
	}
	if !role(w, session, roles...) {
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
	var body struct {
		InstallationID string             `json:"installation_id"`
		GroupID        string             `json:"group_id"`
		Enabled        *bool              `json:"enabled"`
		Endpoint       *nodes.VPNEndpoint `json:"endpoint"`
	}
	if !decode(w, r, &body) {
		return true
	}
	if body.Enabled == nil {
		nodeFailure(w, nodes.ErrInvalid)
		return true
	}
	var result nodes.VPNInstallation
	var replay bool
	err = a.identity.WithAuthorizedSession(r.Context(), token, roles, func(tx pgx.Tx, current identity.Session) error {
		var e error
		result, replay, e = a.nodes.ConfigureVPNTx(r.Context(), tx, nodes.Mutation{ActorID: current.User.ID, Route: r.URL.Path, TargetID: parts[0], Revision: revision, Key: r.Header.Get("Idempotency-Key")}, body.InstallationID, body.GroupID, *body.Enabled, body.Endpoint)
		return e
	})
	if !nodeFailure(w, err) {
		if replay {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		writeJSON(w, 202, result)
	}
	return true
}

// Larger bounded envelope for 128 counter pairs; reject nested duplicate/unknown
// fields so an ACK has one interpretation at both ends.
func decodeNodeDocument(w http.ResponseWriter, r *http.Request, out any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_request")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
	r.Body.Close()
	if err != nil || !utf8.Valid(raw) {
		writeError(w, 400, "invalid_request")
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return errors.New("depth")
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return errors.New("duplicate")
					}
					seen[key] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			default:
				return errors.New("delimiter")
			}
		}
		return nil
	}
	if walk(0) != nil || d.Decode(new(any)) != io.EOF {
		writeError(w, 400, "invalid_request")
		return false
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		writeError(w, 400, "invalid_request")
		return false
	}
	return true
}
