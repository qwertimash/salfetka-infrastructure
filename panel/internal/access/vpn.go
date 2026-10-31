package access

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"salfetka/panel/internal/roomroute"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

// VPNGrantsTx resolves the SAME B2 access rules under user row locks. Only the
// authenticated node-policy issuer may use this private material: never return it
// from an admin list, audit or ordinary access Detail. It does not mark outbox ACKs.
// The caller commits issuance in this transaction before releasing these locks.
func (s *Store) VPNGrantsTx(ctx context.Context, tx pgx.Tx, nodeID, groupID string, generation int64, leaseEnd time.Time, backends ...string) ([]nodewire.VPNGrant, error) {
	backend := ""
	if len(backends) > 1 {
		return nil, ErrInvalid
	}
	if len(backends) == 1 {
		backend = backends[0]
	}
	if !nodewire.ValidBackend(backend) {
		return nil, ErrInvalid
	}
	if !database.ValidID(nodeID) || !database.ValidID(groupID) || generation < 1 || generation > 9007199254740991 {
		return nil, ErrInvalid
	}
	if s.Vault == nil {
		return nil, ErrKey
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return nil, err
	}
	if !leaseEnd.After(now) || leaseEnd.Sub(now) > nodecontrol.MaxVPNLease {
		return nil, ErrInvalid
	}
	// Bounded alpha scan, not a silently truncated policy. Larger groups fail
	// explicitly until batched reconciliation is implemented.
	rows, err := tx.Query(ctx, `SELECT u.id::text FROM access_users u JOIN access_entitlements e ON e.user_id=u.id WHERE e.group_id=$1 ORDER BY u.id LIMIT 513 FOR SHARE OF u`, groupID)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(ids) > 512 {
		return nil, ErrLimit
	}
	var installation string
	var rawEndpoint []byte
	if err = tx.QueryRow(ctx, "SELECT installation_id::text,endpoint FROM nodes_vpn_installations WHERE node_id=$1", nodeID).Scan(&installation, &rawEndpoint); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var routing struct {
		PersonalRooms bool `json:"personal_rooms"`
	}
	if len(rawEndpoint) > 0 && json.Unmarshal(rawEndpoint, &routing) != nil {
		return nil, ErrInvalid
	}
	grants := []nodewire.VPNGrant{}
	for _, id := range ids {
		detail, err := s.DetailTx(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if detail.Entitlement == nil || detail.Entitlement.GroupID != groupID || !detail.Decision.Allowed {
			continue
		}
		room := ""
		if routing.PersonalRooms {
			room, err = roomroute.Lookup(ctx, tx, installation, id)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return nil, err
			}
		}
		expires := leaseEnd
		if detail.Entitlement.ExpiresAt.Before(expires) {
			expires = detail.Entitlement.ExpiresAt
		}
		for _, device := range detail.Devices {
			if !device.Decision.Allowed {
				continue
			}
			if len(grants) >= nodecontrol.MaxVPNGrants {
				return nil, ErrLimit
			}
			credential := device.Credential
			if credential == nil {
				return nil, ErrKey
			}
			var encrypted []byte
			err = tx.QueryRow(ctx, `SELECT ciphertext FROM access_credentials WHERE id=$1 AND user_id=$2 AND device_id=$3 AND version=$4 AND state='active'`, credential.ID, id, device.ID, credential.Version).Scan(&encrypted)
			if err != nil {
				return nil, ErrKey
			}
			plain, err := s.Vault.Open(encrypted, CredentialAAD(id, device.ID, credential.ID, credential.Version))
			if err != nil || len(plain) != 32 {
				clear(plain)
				return nil, ErrKey
			}
			wire := backendCredential(plain, nodeID, credential.ID, backend)
			clear(plain)
			grant := nodewire.VPNGrant{ID: credential.ID, Generation: generation, Enabled: true, Credential: wire, ExpiresAt: expires.UTC()}
			if routing.PersonalRooms {
				grant.AccountID = id
				grant.RoomID = room
			}
			grants = append(grants, grant)
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
	return grants, nil
}

// Independent node/credential scopes; deriving from secret material avoids UUIDs
// predictable from public user IDs. Rotation changes both credential ID and key.
func wireCredential(secret []byte, nodeID, credentialID string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("salfetka-vless-credential-v1\x00" + nodeID + "\x00" + credentialID))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func backendCredential(secret []byte, nodeID, credentialID, backend string) string {
	if backend == "" {
		return wireCredential(secret, nodeID, credentialID)
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("salfetka-managed-key-v1\x00" + backend + "\x00" + nodeID + "\x00" + credentialID))
	b := h.Sum(nil)
	if backend == nodewire.BackendOLCRTC {
		return hex.EncodeToString(b)
	}
	b = b[:16]
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
