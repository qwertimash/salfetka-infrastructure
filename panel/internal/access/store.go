package access

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/secrets"
)

type Store struct {
	Pool  *pgxpool.Pool
	Vault *secrets.Vault
}

func New(pool *pgxpool.Pool, vault *secrets.Vault) *Store { return &Store{pool, vault} }

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

func validName(name string) bool {
	if !utf8.ValidString(name) || name != strings.TrimSpace(name) || utf8.RuneCountInString(name) < 2 || utf8.RuneCountInString(name) > 80 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (s *Store) mutate(ctx context.Context, tx pgx.Tx, m Mutation, out any, fn func() error) (bool, error) {
	if !database.ValidID(m.ActorID) || !keyPattern.MatchString(m.Key) || len(m.Route) > 200 || m.Route == "" || (m.TargetID != "" && !database.ValidID(m.TargetID)) {
		return false, ErrInvalid
	}
	payload, err := json.Marshal(struct {
		Revision int64 `json:"revision"`
		Payload  any   `json:"payload"`
	}{m.Revision, m.Payload})
	if err != nil {
		return false, ErrInvalid
	}
	hash := sha256.Sum256(payload)
	// Serializes duplicate keys before checking revisions, including user creation.
	scope := m.ActorID + "/" + m.Route + "/" + m.TargetID + "/" + m.Key
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", scope); err != nil {
		return false, err
	}
	var previousHash, raw []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,result FROM access_mutations WHERE actor_id=$1 AND route=$2 AND target_id=$3 AND idempotency_key=$4`, m.ActorID, m.Route, m.TargetID, m.Key).Scan(&previousHash, &raw)
	if err == nil {
		if subtle.ConstantTimeCompare(hash[:], previousHash) != 1 {
			return false, ErrConflict
		}
		return true, json.Unmarshal(raw, out)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if m.TargetID != "" {
		var revision int64
		if err = tx.QueryRow(ctx, "SELECT revision FROM access_users WHERE id=$1 FOR UPDATE", m.TargetID).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		} else if err != nil {
			return false, err
		}
		if revision != m.Revision || m.Revision < 1 {
			return false, ErrRevision
		}
	}
	if err = fn(); err != nil {
		return false, err
	}
	raw, err = json.Marshal(out)
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO access_mutations(actor_id,route,target_id,idempotency_key,request_hash,result) VALUES($1,$2,$3,$4,$5,$6)`, m.ActorID, m.Route, m.TargetID, m.Key, hash[:], raw)
	return false, err
}
func bump(ctx context.Context, tx pgx.Tx, userID, actorID, action string) error {
	if _, err := tx.Exec(ctx, `UPDATE access_users SET revision=revision+1,policy_epoch=policy_epoch+1,updated_at=clock_timestamp() WHERE id=$1`, userID); err != nil {
		return err
	}
	return record(ctx, tx, userID, actorID, action)
}
func record(ctx context.Context, tx pgx.Tx, userID, actorID, action string) error {
	id, err := database.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO access_outbox(id,user_id,revision,policy_epoch,kind) SELECT $1,id,revision,policy_epoch,'access.reconcile' FROM access_users WHERE id=$2`, id, userID)
	if err != nil {
		return err
	}
	return audit.Append(ctx, tx, actorID, action, userID, "accepted")
}
func (s *Store) CreateTx(ctx context.Context, tx pgx.Tx, m Mutation, name string) (Detail, bool, error) {
	var out Detail
	m.Payload = struct {
		Name string `json:"name"`
	}{name}
	replay, err := s.mutate(ctx, tx, m, &out, func() error {
		if !validName(name) || m.TargetID != "" || m.Revision != 0 {
			return ErrInvalid
		}
		id, err := database.NewID()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO access_users(id,name) VALUES($1,$2)", id, name); err != nil {
			return err
		}
		if err = record(ctx, tx, id, m.ActorID, "access.user_created"); err != nil {
			return err
		}
		out, err = s.DetailTx(ctx, tx, id)
		return err
	})
	return out, replay, err
}
func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Name, &u.State, &u.Revision, &u.PolicyEpoch, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

const userColumns = "id::text,name,state,revision,policy_epoch,created_at,updated_at"

func (s *Store) ListTx(ctx context.Context, tx pgx.Tx, limit int, cursor string) ([]User, error) {
	if limit < 1 || limit > 100 || (cursor != "" && !database.ValidID(cursor)) {
		return nil, ErrInvalid
	}
	var at time.Time
	if cursor != "" {
		if err := tx.QueryRow(ctx, "SELECT created_at FROM access_users WHERE id=$1", cursor).Scan(&at); errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		} else if err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, "SELECT "+userColumns+" FROM access_users WHERE $1='' OR (created_at,id)<($2,NULLIF($1,'')::uuid) ORDER BY created_at DESC,id DESC LIMIT $3", cursor, at, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Store) GroupsTx(ctx context.Context, tx pgx.Tx) ([]Group, error) {
	rows, err := tx.Query(ctx, "SELECT id::text,name,enabled FROM access_groups ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err = rows.Scan(&g.ID, &g.Name, &g.Enabled); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) DetailTx(ctx context.Context, tx pgx.Tx, id string) (Detail, error) {
	d := Detail{Devices: []Device{}, Blocks: []Block{}}
	if !database.ValidID(id) {
		return d, ErrInvalid
	}
	var err error
	d.User, err = scanUser(tx.QueryRow(ctx, "SELECT "+userColumns+" FROM access_users WHERE id=$1 FOR SHARE", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	e := &Entitlement{}
	groupEnabled := false
	err = tx.QueryRow(ctx, `SELECT e.id::text,e.state,e.expires_at,e.device_limit,e.group_id::text,e.quota_bytes,e.revision,g.enabled FROM access_entitlements e JOIN access_groups g ON g.id=e.group_id WHERE e.user_id=$1`, id).Scan(&e.ID, &e.State, &e.ExpiresAt, &e.DeviceLimit, &e.GroupID, &e.QuotaBytes, &e.Revision, &groupEnabled)
	if err == nil {
		d.Entitlement = e
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return d, err
	}
	rows, err := tx.Query(ctx, `SELECT id::text,scope,device_id::text,reason,active,created_at FROM access_blocks WHERE user_id=$1 ORDER BY created_at,id`, id)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var b Block
		if err = rows.Scan(&b.ID, &b.Scope, &b.DeviceID, &b.Reason, &b.Active, &b.CreatedAt); err != nil {
			rows.Close()
			return d, err
		}
		d.Blocks = append(d.Blocks, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	rows, err = tx.Query(ctx, `SELECT d.id::text,d.user_id::text,d.name,d.state,d.public_key,d.revision,c.id::text,c.version,c.state FROM access_devices d LEFT JOIN LATERAL (SELECT id,version,state FROM access_credentials WHERE device_id=d.id ORDER BY version DESC LIMIT 1) c ON true WHERE d.user_id=$1 ORDER BY d.created_at,d.id`, id)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var dev Device
		var pub []byte
		var cid, cstate *string
		var version *int64
		if err = rows.Scan(&dev.ID, &dev.UserID, &dev.Name, &dev.State, &pub, &dev.Revision, &cid, &version, &cstate); err != nil {
			rows.Close()
			return d, err
		}
		dev.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
		if cid != nil {
			dev.Credential = &Credential{*cid, *version, *cstate}
		}
		d.Devices = append(d.Devices, dev)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return d, err
	}
	d.Decision = baseDecision(d.User, d.Entitlement, d.Blocks, groupEnabled, now)
	eligible := false
	for i := range d.Devices {
		dev := &d.Devices[i]
		dev.Decision = d.Decision
		if dev.Decision.Allowed {
			switch {
			case dev.State != "registered":
				dev.Decision = deny("device_revoked")
			case dev.Credential == nil || dev.Credential.State != "active":
				dev.Decision = deny("credential_revoked")
			default:
				for _, b := range d.Blocks {
					if b.Active && b.Scope == "device" && b.DeviceID != nil && *b.DeviceID == dev.ID {
						dev.Decision = deny("device_blocked")
					}
				}
			}
		}
		eligible = eligible || dev.Decision.Allowed
	}
	if d.Decision.Allowed && !eligible {
		d.Decision = deny("no_eligible_device")
	}
	err = tx.QueryRow(ctx, "SELECT count(*) FROM access_outbox WHERE user_id=$1 AND status='pending'", id).Scan(&d.OutboxPending)
	return d, err
}
func deny(reason string) Decision { return Decision{false, reason, "not_provisioned"} }
func baseDecision(u User, e *Entitlement, blocks []Block, group bool, now time.Time) Decision {
	if u.State != "active" {
		return deny("user_" + u.State)
	}
	for _, b := range blocks {
		if b.Active && b.Scope == "user" {
			return deny("user_blocked")
		}
	}
	if e == nil {
		return deny("no_entitlement")
	}
	if e.State != "active" && e.State != "expired" {
		return deny("entitlement_" + e.State)
	}
	if !e.ExpiresAt.After(now) || e.State == "expired" {
		return deny("entitlement_expired")
	}
	if !group {
		return deny("group_disabled")
	}
	if e.QuotaBytes != nil {
		return deny("quota_unknown")
	}
	return Decision{true, "eligible", "not_provisioned"}
}
func (s *Store) change(ctx context.Context, tx pgx.Tx, m Mutation, action string, fn func() error) (Detail, bool, error) {
	var out Detail
	replay, err := s.mutate(ctx, tx, m, &out, func() error {
		if err := fn(); err != nil {
			return err
		}
		if err := bump(ctx, tx, m.TargetID, m.ActorID, action); err != nil {
			return err
		}
		var err error
		out, err = s.DetailTx(ctx, tx, m.TargetID)
		return err
	})
	return out, replay, err
}
func (s *Store) StateTx(ctx context.Context, tx pgx.Tx, m Mutation, state string) (Detail, bool, error) {
	m.Payload = state
	return s.change(ctx, tx, m, "access.user_state", func() error {
		if state != "active" && state != "suspended" && state != "deleted" {
			return ErrInvalid
		}
		var current string
		if err := tx.QueryRow(ctx, "SELECT state FROM access_users WHERE id=$1", m.TargetID).Scan(&current); err != nil {
			return err
		}
		if current == "deleted" {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, "UPDATE access_users SET state=$2 WHERE id=$1", m.TargetID, state); err != nil {
			return err
		}
		if state == "deleted" {
			if _, err := tx.Exec(ctx, "UPDATE access_devices SET state='revoked',revision=revision+1 WHERE user_id=$1 AND state='registered'", m.TargetID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "UPDATE access_credentials SET state='revoked' WHERE user_id=$1 AND state='active'", m.TargetID)
			return err
		}
		return nil
	})
}
func (s *Store) EntitlementTx(ctx context.Context, tx pgx.Tx, m Mutation, c EntitlementChange) (Detail, bool, error) {
	m.Payload = c
	return s.change(ctx, tx, m, "access.entitlement_changed", func() error {
		var state, userState string
		var previousExpiry, now time.Time
		var priorRevision int64
		if err := tx.QueryRow(ctx, "SELECT state,clock_timestamp() FROM access_users WHERE id=$1", m.TargetID).Scan(&userState, &now); err != nil {
			return err
		}
		if userState == "deleted" {
			return ErrConflict
		}
		err := tx.QueryRow(ctx, "SELECT state,expires_at,revision FROM access_entitlements WHERE user_id=$1", m.TargetID).Scan(&state, &previousExpiry, &priorRevision)
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		terminal := state == "revoked" || state == "refunded"
		switch c.Action {
		case "set", "restore":
			if c.ExpiresAt == nil || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.AddDate(20, 0, 0)) || c.DeviceLimit == nil || *c.DeviceLimit < 1 || *c.DeviceLimit > 100 || c.GroupID == nil || !database.ValidID(*c.GroupID) || (c.QuotaBytes != nil && (*c.QuotaBytes <= 0 || *c.QuotaBytes > 1000000000000000)) {
				return ErrInvalid
			}
			if c.Action == "set" && terminal {
				return ErrTerminal
			}
			if c.Action == "restore" && !terminal {
				return ErrConflict
			}
			var enabled bool
			if err = tx.QueryRow(ctx, "SELECT enabled FROM access_groups WHERE id=$1", *c.GroupID).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalid
			} else if err != nil {
				return err
			}
			if !enabled {
				return ErrInvalid
			}
			var count int
			if err = tx.QueryRow(ctx, "SELECT count(*) FROM access_devices WHERE user_id=$1 AND state='registered'", m.TargetID).Scan(&count); err != nil {
				return err
			}
			if count > *c.DeviceLimit {
				return ErrLimit
			}
			entitlementID, idErr := database.NewID()
			if idErr != nil {
				return idErr
			}
			_, err = tx.Exec(ctx, `INSERT INTO access_entitlements(user_id,state,expires_at,device_limit,group_id,quota_bytes,revision,id) VALUES($1,'active',$2,$3,$4,$5,1,$6) ON CONFLICT(user_id) DO UPDATE SET state='active',expires_at=excluded.expires_at,device_limit=excluded.device_limit,group_id=excluded.group_id,quota_bytes=excluded.quota_bytes,revision=access_entitlements.revision+1`, m.TargetID, *c.ExpiresAt, *c.DeviceLimit, *c.GroupID, c.QuotaBytes, entitlementID)
			return err
		case "renew":
			if c.ExpiresAt == nil || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(previousExpiry) || c.ExpiresAt.After(now.AddDate(20, 0, 0)) || c.DeviceLimit != nil || c.GroupID != nil || c.QuotaBytes != nil {
				return ErrInvalid
			}
			if !exists {
				return ErrNotFound
			}
			if terminal {
				return ErrTerminal
			}
			_, err = tx.Exec(ctx, "UPDATE access_entitlements SET state='active',expires_at=$2,revision=revision+1 WHERE user_id=$1", m.TargetID, *c.ExpiresAt)
			return err
		case "revoke", "refund":
			if c.ExpiresAt != nil || c.DeviceLimit != nil || c.GroupID != nil || c.QuotaBytes != nil {
				return ErrInvalid
			}
			if !exists {
				return ErrNotFound
			}
			if terminal {
				return ErrTerminal
			}
			next := "revoked"
			if c.Action == "refund" {
				next = "refunded"
			}
			if _, err = tx.Exec(ctx, "UPDATE access_entitlements SET state=$2,revision=revision+1 WHERE user_id=$1", m.TargetID, next); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, "UPDATE access_credentials SET state='revoked' WHERE user_id=$1 AND state='active'", m.TargetID)
			return err
		default:
			return ErrInvalid
		}
	})
}
func (s *Store) BlockTx(ctx context.Context, tx pgx.Tx, m Mutation, c BlockChange) (Detail, bool, error) {
	m.Payload = c
	return s.change(ctx, tx, m, "access.block_added", func() error {
		if c.Reason != "policy" && c.Reason != "abuse" && c.Reason != "security" && c.Reason != "manual" {
			return ErrInvalid
		}
		if c.Scope == "user" {
			if c.DeviceID != nil {
				return ErrInvalid
			}
		} else if c.Scope == "device" {
			if c.DeviceID == nil || !database.ValidID(*c.DeviceID) {
				return ErrInvalid
			}
			var found bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_devices WHERE user_id=$1 AND id=$2)", m.TargetID, *c.DeviceID).Scan(&found); err != nil {
				return err
			}
			if !found {
				return ErrNotFound
			}
		} else {
			return ErrInvalid
		}
		var found bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE user_id=$1 AND scope=$2 AND device_id IS NOT DISTINCT FROM $3::uuid AND active)", m.TargetID, c.Scope, c.DeviceID).Scan(&found); err != nil {
			return err
		}
		if found {
			return ErrConflict
		}
		id, err := database.NewID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO access_blocks(id,user_id,scope,device_id,reason) VALUES($1,$2,$3,$4,$5)", id, m.TargetID, c.Scope, c.DeviceID, c.Reason)
		return err
	})
}
func (s *Store) ClearBlockTx(ctx context.Context, tx pgx.Tx, m Mutation, id string) (Detail, bool, error) {
	m.Payload = id
	return s.change(ctx, tx, m, "access.block_cleared", func() error {
		if !database.ValidID(id) {
			return ErrInvalid
		}
		tag, err := tx.Exec(ctx, "UPDATE access_blocks SET active=false,cleared_at=clock_timestamp() WHERE id=$1 AND user_id=$2 AND active", id, m.TargetID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return nil
	})
}

// ReconcileExpired persists an expiry tombstone and pending intent exactly once.
// Logical decisions already reject an expired timestamp before this worker runs.
func (s *Store) ReconcileExpired(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 100 {
		return 0, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer database.Rollback(tx)
	// Lock order is always user before entitlement, matching all operator mutations.
	rows, err := tx.Query(ctx, `SELECT u.id::text FROM access_users u WHERE EXISTS(SELECT 1 FROM access_entitlements e WHERE e.user_id=u.id AND e.state='active' AND e.expires_at<=clock_timestamp()) ORDER BY u.id LIMIT $1 FOR UPDATE OF u SKIP LOCKED`, limit)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		tag, err := tx.Exec(ctx, "UPDATE access_entitlements SET state='expired',revision=revision+1 WHERE user_id=$1 AND state='active' AND expires_at<=clock_timestamp()", id)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		if err = bump(ctx, tx, id, "worker", "access.entitlement_expired"); err != nil {
			return 0, err
		}
		count++
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}
func CredentialAAD(userID, deviceID, credentialID string, version int64) string {
	return fmt.Sprintf("salfetka:device-access:v1:%s:%s:%s:%d", userID, deviceID, credentialID, version)
}
