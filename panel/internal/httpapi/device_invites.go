package httpapi

import (
	"crypto/sha256"
	"net/http"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/builder"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/subscriptionsets"
	"strings"
)

func (a *api) serveDeviceInvite(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/i/")
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || !tokenPatternPublic.MatchString(token) {
		writeError(w, 404, "not_found")
		return
	}
	select {
	case a.subscriptionSlots <- struct{}{}:
		defer func() { <-a.subscriptionSlots }()
	default:
		writeError(w, 429, "busy")
		return
	}
	if r.Method == http.MethodGet {
		hash := sha256.Sum256([]byte(token))
		var user string
		e := a.pool.QueryRow(r.Context(), `SELECT i.user_id::text FROM access_device_invites i JOIN account_set_assignments a ON a.id=i.assignment_id AND a.revision=i.assignment_revision AND a.state='active' JOIN access_users u ON u.id=i.user_id AND u.state='active' WHERE i.token_hash=$1 AND i.expires_at>clock_timestamp()`, hash[:]).Scan(&user)
		if e != nil {
			writeError(w, 404, "not_found")
			return
		}
		// Opaque account ID only. Possession/entitlement are checked again on POST.
		writeJSON(w, 200, map[string]any{"type": "salfetka-device-invite", "version": 1, "user_id": user})
		return
	}
	var proof access.InviteProof
	if !decodeRelease(w, r, &proof) {
		return
	}
	if a.config.Vault == nil {
		writeError(w, 503, "key_unavailable")
		return
	}
	tx, e := a.pool.Begin(r.Context())
	if e != nil {
		writeError(w, 503, "subscription_unavailable")
		return
	}
	defer database.Rollback(tx)
	result, e := access.New(a.pool, a.config.Vault).ConsumeInviteTx(r.Context(), tx, token, proof)
	if e != nil {
		writeError(w, 404, "not_found")
		return
	}
	store := subscriptionsets.Store{Builder: builder.New(a.pool, a.config.Vault)}
	link, e := store.AssignmentLinkTx(r.Context(), tx, "system", result.AssignmentID)
	if e != nil {
		writeError(w, 503, "subscription_unavailable")
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		writeError(w, 503, "subscription_unavailable")
		return
	}
	writeJSON(w, 200, map[string]string{"device_id": result.DeviceID, "user_id": result.UserID, "url": a.config.SubscriptionOrigin + "/a/" + link})
}
