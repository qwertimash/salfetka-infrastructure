// Package access owns the independent customer access model. Decisions are logical
// authorization only; B2 has no node provisioning or engine credentials.
package access

import (
	"errors"
	"time"
)

var (
	ErrInvalid          = errors.New("access_invalid")
	ErrNotFound         = errors.New("access_not_found")
	ErrConflict         = errors.New("access_conflict")
	ErrRevision         = errors.New("access_revision")
	ErrTerminal         = errors.New("terminal_entitlement")
	ErrLimit            = errors.New("device_limit")
	ErrProof            = errors.New("proof_invalid")
	ErrBound            = errors.New("device_bound")
	ErrChallengeExpired = errors.New("challenge_expired")
	ErrChallengeUsed    = errors.New("challenge_used")
	ErrKey              = errors.New("key_unavailable")
)

const DefaultGroupID = "00000000-0000-4000-8000-000000000001"

type User struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	State       string    `json:"state"`
	Revision    int64     `json:"revision"`
	PolicyEpoch int64     `json:"policy_epoch"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type Entitlement struct {
	// Before migration 004, persisted idempotency snapshots omitted this field.
	// Fresh reads always include the UUID; old retries preserve their snapshot.
	ID          string    `json:"id,omitempty"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expires_at"`
	DeviceLimit int       `json:"device_limit"`
	GroupID     string    `json:"group_id"`
	QuotaBytes  *int64    `json:"quota_bytes"`
	Revision    int64     `json:"revision"`
}
type Credential struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	State   string `json:"state"`
}
type Decision struct {
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	NodeState string `json:"node_state"`
}
type Device struct {
	ID         string      `json:"id"`
	UserID     string      `json:"user_id"`
	Name       string      `json:"name"`
	State      string      `json:"state"`
	PublicKey  string      `json:"public_key"`
	Revision   int64       `json:"revision"`
	Credential *Credential `json:"credential"`
	Decision   Decision    `json:"decision"`
}
type Block struct {
	ID        string    `json:"id"`
	Scope     string    `json:"scope"`
	DeviceID  *string   `json:"device_id"`
	Reason    string    `json:"reason"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}
type Detail struct {
	User          User         `json:"user"`
	Entitlement   *Entitlement `json:"entitlement"`
	Devices       []Device     `json:"devices"`
	Blocks        []Block      `json:"blocks"`
	Decision      Decision     `json:"decision"`
	OutboxPending int          `json:"outbox_pending"`
}
type Group struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}
type EntitlementChange struct {
	Action      string     `json:"action"`
	ExpiresAt   *time.Time `json:"expires_at"`
	DeviceLimit *int       `json:"device_limit"`
	GroupID     *string    `json:"group_id"`
	QuotaBytes  *int64     `json:"quota_bytes"`
}
type BlockChange struct {
	Scope    string  `json:"scope"`
	DeviceID *string `json:"device_id"`
	Reason   string  `json:"reason"`
}
type Challenge struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	PublicKey      string    `json:"public_key"`
	SigningMessage string    `json:"signing_message"`
	ExpiresAt      time.Time `json:"expires_at"`
	UserRevision   int64     `json:"user_revision"`
}
type Register struct {
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
	Name        string `json:"name"`
}

// Mutation is fixed by the HTTP route, never supplied by an untrusted body.
type Mutation struct {
	ActorID, Route, TargetID, Key string
	Revision                      int64
	Payload                       any
}
