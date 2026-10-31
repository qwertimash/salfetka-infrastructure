package subscriptionsets

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/releases"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// AssignmentLinkTx explicitly reveals a secret to an authorized operator; list
// and publication projections never expose either account or device tokens.
func (s *Store) AssignmentLinkTx(ctx context.Context, tx pgx.Tx, actor, id string) (string, error) {
	if !database.ValidID(id) || s.Builder == nil || s.Builder.Vault == nil {
		return "", ErrInvalid
	}
	var user string
	if e := tx.QueryRow(ctx, "SELECT user_id::text FROM account_set_assignments WHERE id=$1", id).Scan(&user); e != nil {
		return "", ErrNotFound
	}
	var state string
	if e := tx.QueryRow(ctx, "SELECT state FROM access_users WHERE id=$1 FOR SHARE", user).Scan(&state); e != nil || state != "active" {
		return "", releases.ErrDenied
	}
	var generation int64
	var cipher []byte
	if e := tx.QueryRow(ctx, "SELECT state,revision,token_ciphertext FROM account_set_assignments WHERE id=$1 FOR UPDATE", id).Scan(&state, &generation, &cipher); e != nil || state != "active" {
		return "", releases.ErrDenied
	}
	aad := fmt.Sprintf("assignment-link:%s:%d", id, generation)
	var token string
	if len(cipher) == 0 {
		var e error
		token, e = identity.RandomToken()
		if e != nil {
			return "", e
		}
		cipher, e = s.Builder.Vault.Seal([]byte(token), aad)
		if e != nil {
			return "", e
		}
		hash := sha256.Sum256([]byte(token))
		if _, e = tx.Exec(ctx, "UPDATE account_set_assignments SET token_hash=$2,token_ciphertext=$3 WHERE id=$1", id, hash[:], cipher); e != nil {
			return "", e
		}
	} else {
		plain, e := s.Builder.Vault.Open(cipher, aad)
		if e != nil {
			return "", e
		}
		token = string(plain)
		clear(plain)
	}
	if e := audit.Append(ctx, tx, actor, "subscription_set.link", id, "succeeded"); e != nil {
		return "", e
	}
	return token, nil
}

type DeviceProof struct {
	DeviceID  string `json:"device_id"`
	IssuedAt  int64  `json:"issued_at"`
	Signature string `json:"signature"`
}

// ProofMessage binds the assignment token, physical-device ID and a short
// timestamp window. Replaying the read within that window returns the same URL;
// it cannot enroll a device, rotate keys, or create a new session/grant.
func ProofMessage(token, device string, issued int64) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("salfetka-set-resolve-v1\n%x\n%s\n%d", hash, device, issued)
}
func (s *Store) Resolve(ctx context.Context, engine *releases.Store, token string, proof DeviceProof) (string, error) {
	if !tokenPattern.MatchString(token) || !database.ValidID(proof.DeviceID) {
		return "", releases.ErrDenied
	}
	sig, e := base64.RawURLEncoding.DecodeString(proof.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return "", releases.ErrDenied
	}
	tx, e := s.Builder.Pool.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer database.Rollback(tx)
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return "", e
	}
	if proof.IssuedAt < now.Unix()-60 || proof.IssuedAt > now.Unix()+10 {
		return "", releases.ErrDenied
	}
	hash := sha256.Sum256([]byte(token))
	var assignment, user string
	var generation int64
	if e = tx.QueryRow(ctx, "SELECT id::text,user_id::text,revision FROM account_set_assignments WHERE token_hash=$1 AND state='active'", hash[:]).Scan(&assignment, &user, &generation); e != nil {
		return "", releases.ErrDenied
	}
	var key []byte
	if e = tx.QueryRow(ctx, "SELECT public_key FROM access_devices WHERE id=$1 AND user_id=$2 AND state='registered'", proof.DeviceID, user).Scan(&key); e != nil || len(key) != ed25519.PublicKeySize {
		return "", releases.ErrDenied
	}
	if !ed25519.Verify(ed25519.PublicKey(key), []byte(ProofMessage(token, proof.DeviceID, proof.IssuedAt)), sig) {
		return "", releases.ErrDenied
	}
	scoped := *engine
	scoped.AssignmentID = assignment
	scoped.AssignmentRevision = generation
	// LinkTx reacquires current account/assignment locks and enforces entitlement,
	// device revocation and generation before returning the published device URL.
	link, e := scoped.LinkTx(ctx, tx, "system", user, proof.DeviceID)
	if e != nil {
		return "", e
	}
	if e = tx.Commit(ctx); e != nil {
		return "", e
	}
	return link, nil
}

// DeviceLinkTx is an explicit privileged compatibility action for an already
// registered device. It does not enroll a synthetic device for the operator.
func (s *Store) DeviceLinkTx(ctx context.Context, tx pgx.Tx, engine *releases.Store, actor, assignment, device string) (string, error) {
	if !database.ValidID(assignment) || !database.ValidID(device) {
		return "", ErrInvalid
	}
	var user string
	var generation int64
	if e := tx.QueryRow(ctx, "SELECT user_id::text,revision FROM account_set_assignments WHERE id=$1 AND state='active'", assignment).Scan(&user, &generation); e != nil {
		return "", ErrNotFound
	}
	scoped := *engine
	scoped.AssignmentID = assignment
	scoped.AssignmentRevision = generation
	return scoped.LinkTx(ctx, tx, actor, user, device)
}
