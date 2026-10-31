package access

import (
	"context"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
	"time"
)

// Export is an explicit private read under the same user lock as access changes.
// It never stores the plaintext result in idempotency, audit or list projections.
func (s *Store) VPNCredentialTx(ctx context.Context, tx pgx.Tx, userID, deviceID, nodeID, groupID string, backends ...string) (string, string, error) {
	backend := ""
	if len(backends) > 1 {
		return "", "", ErrInvalid
	}
	if len(backends) == 1 {
		backend = backends[0]
	}
	if !nodewire.ValidBackend(backend) {
		return "", "", ErrInvalid
	}
	if !database.ValidID(userID) || !database.ValidID(deviceID) || !database.ValidID(nodeID) || !database.ValidID(groupID) {
		return "", "", ErrInvalid
	}
	if s.Vault == nil {
		return "", "", ErrKey
	}
	if _, e := tx.Exec(ctx, "SELECT id FROM access_users WHERE id=$1 FOR SHARE", userID); e != nil {
		return "", "", e
	}
	d, e := s.DetailTx(ctx, tx, userID)
	if e != nil {
		return "", "", e
	}
	if !d.Decision.Allowed || d.Entitlement == nil || d.Entitlement.GroupID != groupID {
		return "", "", ErrConflict
	}
	for _, device := range d.Devices {
		if device.ID != deviceID {
			continue
		}
		if !device.Decision.Allowed || device.Credential == nil {
			return "", "", ErrConflict
		}
		credential := device.Credential
		var encrypted []byte
		var now time.Time
		if e = tx.QueryRow(ctx, "SELECT ciphertext,clock_timestamp() FROM access_credentials WHERE id=$1 AND state='active'", credential.ID).Scan(&encrypted, &now); e != nil {
			return "", "", ErrKey
		}
		if !d.Entitlement.ExpiresAt.After(now) {
			return "", "", ErrConflict
		}
		plain, e := s.Vault.Open(encrypted, CredentialAAD(userID, deviceID, credential.ID, credential.Version))
		if e != nil || len(plain) != 32 {
			clear(plain)
			return "", "", ErrKey
		}
		defer clear(plain)
		return credential.ID, backendCredential(plain, nodeID, credential.ID, backend), nil
	}
	return "", "", ErrNotFound
}
