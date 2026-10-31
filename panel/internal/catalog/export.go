package catalog

import (
	"context"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"time"
)

// FrozenTx returns private compiler input, never an HTTP/audit projection.
// New releases must pin the current reviewed version. Historical reads are only
// for a recipe already frozen by the release store (rollback / delivery).
func (s *Store) FrozenTx(ctx context.Context, tx pgx.Tx, id, version string, historical bool, now time.Time) (compiler.Source, error) {
	if !database.ValidID(id) || !database.ValidID(version) {
		return compiler.Source{}, ErrInvalid
	}
	var current *string
	if e := tx.QueryRow(ctx, "SELECT current_version::text FROM catalog_sources WHERE id=$1 FOR SHARE", id).Scan(&current); e != nil {
		return compiler.Source{}, ErrNotFound
	}
	if !historical && (current == nil || *current != version) {
		return compiler.Source{}, ErrRevision
	}
	var cipher []byte
	if e := tx.QueryRow(ctx, "SELECT body_ciphertext FROM catalog_versions WHERE source_id=$1 AND id=$2", id, version).Scan(&cipher); e != nil {
		return compiler.Source{}, ErrNotFound
	}
	doc, e := s.document(cipher, "version:"+id+":"+version)
	if e != nil {
		return compiler.Source{}, e
	}
	p, e := prepare(doc, now)
	if e != nil {
		return compiler.Source{}, e
	}
	return compiler.Source{ID: id, VersionID: version, Digest: p.Preview.Digest, Format: p.Preview.Format, Normalized: p.document.Normalized, ValidUntil: p.Preview.ValidUntil, ExpiresAt: p.Preview.SubscriptionExpiresAt}, nil
}
