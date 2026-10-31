package access

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
)

func publicKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != encoded {
		return nil, ErrInvalid
	}
	return key, nil
}
func (s *Store) admission(ctx context.Context, tx pgx.Tx, userID string) error {
	d, err := s.DetailTx(ctx, tx, userID)
	if err != nil {
		return err
	}
	var enabled bool
	var now time.Time
	if d.Entitlement != nil {
		if err = tx.QueryRow(ctx, "SELECT enabled,clock_timestamp() FROM access_groups WHERE id=$1", d.Entitlement.GroupID).Scan(&enabled, &now); err != nil {
			return err
		}
	}
	if !baseDecision(d.User, d.Entitlement, d.Blocks, enabled, now).Allowed {
		return ErrConflict
	}
	return nil
}
func (s *Store) ChallengeTx(ctx context.Context, tx pgx.Tx, m Mutation, keyString string) (Challenge, bool, error) {
	m.Payload = keyString
	var out Challenge
	replay, err := s.mutate(ctx, tx, m, &out, func() error {
		key, err := publicKey(keyString)
		if err != nil {
			return err
		}
		if err = s.admission(ctx, tx, m.TargetID); err != nil {
			return err
		}
		var count int
		if err = tx.QueryRow(ctx, "SELECT count(*) FROM access_challenges WHERE user_id=$1 AND used_at IS NULL AND expires_at>clock_timestamp()", m.TargetID).Scan(&count); err != nil {
			return err
		}
		if count >= 10 {
			return ErrLimit
		}
		id, err := database.NewID()
		if err != nil {
			return err
		}
		nonce := make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			return err
		}
		var expires time.Time
		if err = tx.QueryRow(ctx, "SELECT date_trunc('second',clock_timestamp())+interval '5 minutes'").Scan(&expires); err != nil {
			return err
		}
		message := fmt.Sprintf("salfetka-device-proof-v1\n%s\n%s\n%s\n%s\n%s", m.TargetID, id, keyString, expires.UTC().Format(time.RFC3339), base64.RawURLEncoding.EncodeToString(nonce))
		if _, err = tx.Exec(ctx, "INSERT INTO access_challenges(id,user_id,public_key,signing_message,expires_at) VALUES($1,$2,$3,$4,$5)", id, m.TargetID, key, message, expires); err != nil {
			return err
		}
		if err = bump(ctx, tx, m.TargetID, m.ActorID, "access.challenge_created"); err != nil {
			return err
		}
		var revision int64
		if err = tx.QueryRow(ctx, "SELECT revision FROM access_users WHERE id=$1", m.TargetID).Scan(&revision); err != nil {
			return err
		}
		out = Challenge{id, m.TargetID, keyString, message, expires, revision}
		return nil
	})
	return out, replay, err
}
func (s *Store) RegisterTx(ctx context.Context, tx pgx.Tx, m Mutation, r Register) (Detail, bool, error) {
	m.Payload = r
	return s.change(ctx, tx, m, "access.device_registered", func() error {
		if !database.ValidID(r.ChallengeID) || !validName(r.Name) {
			return ErrInvalid
		}
		signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != r.Signature {
			return ErrProof
		}
		var key []byte
		var message string
		var expires, now time.Time
		var used *time.Time
		err = tx.QueryRow(ctx, "SELECT public_key,signing_message,expires_at,used_at,clock_timestamp() FROM access_challenges WHERE id=$1 AND user_id=$2 FOR UPDATE", r.ChallengeID, m.TargetID).Scan(&key, &message, &expires, &used, &now)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProof
		}
		if err != nil {
			return err
		}
		if used != nil {
			return ErrChallengeUsed
		}
		if !expires.After(now) {
			return ErrChallengeExpired
		}
		if !ed25519.Verify(key, []byte(message), signature) {
			return ErrProof
		}
		if err = s.admission(ctx, tx, m.TargetID); err != nil {
			return err
		}
		if _, err = s.registerKeyTx(ctx, tx, m.TargetID, key, r.Name); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE access_challenges SET used_at=clock_timestamp() WHERE id=$1", r.ChallengeID)
		return err
	})
}

// Caller holds the account row lock and has verified possession of the key and
// current admission. Shared by admin challenges and short-lived invite proof.
func (s *Store) registerKeyTx(ctx context.Context, tx pgx.Tx, user string, key []byte, name string) (string, error) {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,1))", base64.RawURLEncoding.EncodeToString(key)); err != nil {
		return "", err
	}
	var id, owner, state string
	err := tx.QueryRow(ctx, "SELECT id::text,user_id::text,state FROM access_devices WHERE public_key=$1", key).Scan(&id, &owner, &state)
	if err == nil {
		if owner != user || state != "registered" {
			return "", ErrBound
		}
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	var count, limit int
	if err = tx.QueryRow(ctx, "SELECT e.device_limit,(SELECT count(*) FROM access_devices WHERE user_id=$1 AND state='registered') FROM access_entitlements e WHERE e.user_id=$1", user).Scan(&limit, &count); err != nil {
		return "", err
	}
	if count >= limit {
		return "", ErrLimit
	}
	if s.Vault == nil {
		return "", ErrKey
	}
	id, err = database.NewID()
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO access_devices(id,user_id,name,state,public_key) VALUES($1,$2,$3,'registered',$4)", id, user, name, key); err != nil {
		return "", err
	}
	if err = s.credential(ctx, tx, user, id); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) credential(ctx context.Context, tx pgx.Tx, userID, deviceID string) error {
	if s.Vault == nil {
		return ErrKey
	}
	var version int64
	if err := tx.QueryRow(ctx, "SELECT coalesce(max(version),0)+1 FROM access_credentials WHERE device_id=$1", deviceID).Scan(&version); err != nil {
		return err
	}
	id, err := database.NewID()
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return err
	}
	defer clear(secret)
	ciphertext, err := s.Vault.Seal(secret, CredentialAAD(userID, deviceID, id, version))
	if err != nil {
		return ErrKey
	}
	if _, err = tx.Exec(ctx, "UPDATE access_credentials SET state='revoked' WHERE device_id=$1 AND state='active'", deviceID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO access_credentials(id,user_id,device_id,version,state,ciphertext) VALUES($1,$2,$3,$4,'active',$5)", id, userID, deviceID, version, ciphertext)
	return err
}
func (s *Store) DeviceTx(ctx context.Context, tx pgx.Tx, m Mutation, deviceID, action string) (Detail, bool, error) {
	m.Payload = struct{ DeviceID, Action string }{deviceID, action}
	event := "access.device_revoked"
	if action == "rotate" {
		event = "access.credential_rotated"
	}
	return s.change(ctx, tx, m, event, func() error {
		if !database.ValidID(deviceID) || (action != "revoke" && action != "rotate") {
			return ErrInvalid
		}
		var state string
		if err := tx.QueryRow(ctx, "SELECT state FROM access_devices WHERE id=$1 AND user_id=$2", deviceID, m.TargetID).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if state != "registered" {
			return ErrConflict
		}
		if action == "rotate" {
			var blocked bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE user_id=$1 AND device_id=$2 AND active)", m.TargetID, deviceID).Scan(&blocked); err != nil {
				return err
			}
			if blocked {
				return ErrConflict
			}
			if err := s.admission(ctx, tx, m.TargetID); err != nil {
				return err
			}
			if err := s.credential(ctx, tx, m.TargetID, deviceID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "UPDATE access_devices SET revision=revision+1 WHERE id=$1", deviceID)
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE access_devices SET state='revoked',revision=revision+1 WHERE id=$1", deviceID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE access_credentials SET state='revoked' WHERE device_id=$1 AND state='active'", deviceID)
		return err
	})
}
