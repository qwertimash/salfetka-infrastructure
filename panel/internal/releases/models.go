// Package releases owns immutable subscription revisions and current assignments.
package releases

import (
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/secrets"
	"time"
)

var ErrInvalid = errors.New("release_invalid")
var ErrConflict = errors.New("release_conflict")
var ErrDenied = errors.New("subscription_denied")
var ErrUnavailable = errors.New("subscription_unavailable")
var ErrCapacity = errors.New("release_capacity")

type Store struct {
	// Assignment scope is server-only; legacy HTTP callers leave it empty.
	AssignmentID       string
	AssignmentRevision int64
	Pool               *pgxpool.Pool
	Vault              *secrets.Vault
	Access             *access.Store
	Catalog            *catalog.Store
	Nodes              *nodes.Store
}

func New(p *pgxpool.Pool, v *secrets.Vault, n *nodes.Store) *Store {
	return &Store{Pool: p, Vault: v, Access: access.New(p, v), Catalog: catalog.New(p, v), Nodes: n}
}

type SourceRef struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
}
type Recipe struct {
	Title     string              `json:"title,omitempty"`
	Blueprint *compiler.Blueprint `json:"blueprint,omitempty"`
	Sources   []SourceRef         `json:"sources,omitempty"`
	// Set only by the compiler; incoming stage requests must not supply bindings.
	NodeBindings        map[string]string `json:"node_bindings,omitempty"`
	SourceID            string            `json:"source_id"`
	VersionID           string            `json:"version_id"`
	ExternalCredentials bool              `json:"external_credentials"`
	NodeIDs             []string          `json:"node_ids"`
	Network             json.RawMessage   `json:"network,omitempty"`
	Locations           json.RawMessage   `json:"locations,omitempty"`
	MaxVersion          int               `json:"max_version"`
	Engines             []string          `json:"engines"`
}
type Mutation struct {
	DraftID       string  `json:"draft_id,omitempty"`
	DraftRevision int64   `json:"draft_revision,omitempty"`
	Actor         string  `json:"-"`
	Key           string  `json:"-"`
	Operation     string  `json:"operation"`
	UserID        string  `json:"user_id"`
	DeviceID      string  `json:"device_id"`
	Revision      int64   `json:"revision"`
	ReleaseID     string  `json:"release_id"`
	TokenRevision int64   `json:"token_revision"`
	Recipe        *Recipe `json:"recipe,omitempty"`
}
type Subscription struct {
	ID            string  `json:"id"`
	UserID        string  `json:"user_id"`
	DeviceID      string  `json:"device_id"`
	Revision      int64   `json:"revision"`
	ActiveRelease *string `json:"active_release"`
	TokenActive   bool    `json:"token_active"`
	TokenRevision int64   `json:"token_revision"`
}
type Check struct {
	NodeID string `json:"node_id"`
	State  string `json:"state"`
}
type Release struct {
	ID         string           `json:"id"`
	Number     int64            `json:"number"`
	State      string           `json:"state"`
	Digest     string           `json:"digest"`
	Preview    importer.Preview `json:"preview"`
	Provenance json.RawMessage  `json:"provenance"`
	Checks     []Check          `json:"checks"`
	CreatedAt  time.Time        `json:"created_at"`
}
type Detail struct {
	Subscription Subscription `json:"subscription"`
	Releases     []Release    `json:"releases"`
}
