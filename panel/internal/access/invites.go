package access

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
)

type Invitation struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MintInviteTx requires an authorized administrative transaction. It never
// registers a synthetic device. Retry cannot extend the life of an old invite.
func (s *Store) MintInviteTx(ctx context.Context, tx pgx.Tx, actor, assignment, requestKey string) (Invitation, bool, error) {
	var out Invitation
	if !database.ValidID(actor) || !database.ValidID(assignment) || !keyPattern.MatchString(requestKey) || s.Vault == nil {
		return out, false, ErrInvalid
	}
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "invite/"+actor+"/"+requestKey); e != nil {
		return out, false, e
	}
	var id, previous string
	var cipher []byte
	e := tx.QueryRow(ctx, "SELECT id::text,assignment_id::text,token_ciphertext,expires_at FROM access_device_invites WHERE actor_id=$1 AND idempotency_key=$2", actor, requestKey).Scan(&id, &previous, &cipher, &out.ExpiresAt)
	if e == nil {
		if previous != assignment {
			return out, false, ErrConflict
		}
		raw, e := s.Vault.Open(cipher, "device-invite:"+id)
		if e != nil {
			return out, false, ErrKey
		}
		out.Token = string(raw)
		clear(raw)
		return out, true, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return out, false, e
	}
	var user, state string
	var revision int64
	if e = tx.QueryRow(ctx, "SELECT user_id::text FROM account_set_assignments WHERE id=$1", assignment).Scan(&user); e != nil {
		return out, false, ErrNotFound
	}
	if e = tx.QueryRow(ctx, "SELECT state FROM access_users WHERE id=$1 FOR UPDATE", user).Scan(&state); e != nil {
		return out, false, e
	}
	if e = s.admission(ctx, tx, user); e != nil {
		return out, false, e
	}
	if e = tx.QueryRow(ctx, "SELECT revision,state FROM account_set_assignments WHERE id=$1 FOR SHARE", assignment).Scan(&revision, &state); e != nil || state != "active" {
		return out, false, ErrConflict
	}
	var count int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM access_device_invites WHERE user_id=$1 AND device_id IS NULL AND expires_at>clock_timestamp()", user).Scan(&count); e != nil {
		return out, false, e
	}
	if count >= 5 {
		return out, false, ErrLimit
	}
	id, e = database.NewID()
	if e != nil {
		return out, false, e
	}
	out.Token, e = identity.RandomToken()
	if e != nil {
		return out, false, e
	}
	cipher, e = s.Vault.Seal([]byte(out.Token), "device-invite:"+id)
	if e != nil {
		return out, false, ErrKey
	}
	hash := sha256.Sum256([]byte(out.Token))
	e = tx.QueryRow(ctx, `INSERT INTO access_device_invites(id,assignment_id,assignment_revision,user_id,actor_id,idempotency_key,token_hash,token_ciphertext,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+interval '30 minutes') RETURNING expires_at`, id, assignment, revision, user, actor, requestKey, hash[:], cipher).Scan(&out.ExpiresAt)
	if e == nil {
		e = audit.Append(ctx, tx, actor, "access.invite_created", user, "succeeded")
	}
	return out, false, e
}

type InviteProof struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	IssuedAt  int64  `json:"issued_at"`
	Name      string `json:"name"`
}
type EnrolledDevice struct {
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	AssignmentID string `json:"-"`
}

func InviteMessage(token string, p InviteProof) string {
	tokenHash, nameHash := sha256.Sum256([]byte(token)), sha256.Sum256([]byte(p.Name))
	return fmt.Sprintf("salfetka-device-invite-v1\n%x\n%s\n%d\n%x", tokenHash, p.PublicKey, p.IssuedAt, nameHash)
}

// ConsumeInviteTx serializes against revocation/limit changes. Same key retries
// recover a lost response; another key never consumes an already used invite.
func (s *Store) ConsumeInviteTx(ctx context.Context, tx pgx.Tx, token string, p InviteProof) (EnrolledDevice, error) {
	var out EnrolledDevice
	raw, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return out, ErrProof
	}
	key, e := publicKey(p.PublicKey)
	if e != nil || !validName(p.Name) {
		return out, ErrProof
	}
	sig, e := base64.RawURLEncoding.DecodeString(p.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(InviteMessage(token, p)), sig) {
		return out, ErrProof
	}
	hash := sha256.Sum256([]byte(token))
	if e = tx.QueryRow(ctx, "SELECT user_id::text FROM access_device_invites WHERE token_hash=$1", hash[:]).Scan(&out.UserID); e != nil {
		return out, ErrProof
	}
	var state string
	if e = tx.QueryRow(ctx, "SELECT state FROM access_users WHERE id=$1 FOR UPDATE", out.UserID).Scan(&state); e != nil {
		return out, e
	}
	var id string
	var device *string
	var revision int64
	var expires, now time.Time
	e = tx.QueryRow(ctx, "SELECT id::text,assignment_id::text,assignment_revision,device_id::text,expires_at,clock_timestamp() FROM access_device_invites WHERE token_hash=$1 FOR UPDATE", hash[:]).Scan(&id, &out.AssignmentID, &revision, &device, &expires, &now)
	if e != nil {
		return out, e
	}
	if !expires.After(now) || p.IssuedAt < now.Unix()-60 || p.IssuedAt > now.Unix()+10 {
		return out, ErrProof
	}
	if e = s.admission(ctx, tx, out.UserID); e != nil {
		return out, ErrProof
	}
	var current int64
	if e = tx.QueryRow(ctx, "SELECT revision,state FROM account_set_assignments WHERE id=$1 FOR SHARE", out.AssignmentID).Scan(&current, &state); e != nil || state != "active" || current != revision {
		return out, ErrProof
	}
	if device != nil {
		var same bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_devices d JOIN access_credentials c ON c.device_id=d.id AND c.state='active' WHERE d.id=$1 AND d.user_id=$2 AND d.public_key=$3 AND d.state='registered' AND NOT EXISTS(SELECT 1 FROM access_blocks WHERE user_id=$2 AND active AND (scope='user' OR device_id=d.id)))`, *device, out.UserID, key).Scan(&same)
		if e != nil {
			return out, e
		}
		if !same {
			return out, ErrProof
		}
		out.DeviceID = *device
		return out, nil
	}
	out.DeviceID, e = s.registerKeyTx(ctx, tx, out.UserID, key, p.Name)
	if e != nil {
		return out, e
	}
	var blocked bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE user_id=$1 AND device_id=$2 AND active)", out.UserID, out.DeviceID).Scan(&blocked); e != nil {
		return out, e
	}
	if blocked {
		return out, ErrProof
	}
	if _, e = tx.Exec(ctx, "UPDATE access_device_invites SET device_id=$2 WHERE id=$1", id, out.DeviceID); e != nil {
		return out, e
	}
	if e = bump(ctx, tx, out.UserID, "system", "access.device_registered"); e != nil {
		return out, e
	}
	return out, nil
}
