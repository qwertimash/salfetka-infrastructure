package catalog

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/importer"
)

// RefreshOne leases one source. Network work never holds a DB transaction or
// blocks access expiry. Multiple workers may run; a stale lease cannot commit.
// Every changed response is a candidate awaiting explicit review, so a truncated
// but syntactically valid subscription cannot silently remove existing records.
func (s *Store) RefreshOne(ctx context.Context) (bool, error) {
	if _, e := s.Pool.Exec(ctx, "DELETE FROM catalog_drafts WHERE expires_at<clock_timestamp()"); e != nil {
		return false, e
	}
	lease, e := database.NewID()
	if e != nil {
		return false, e
	}
	var id, name string
	var ciphertext []byte
	e = s.Pool.QueryRow(ctx, `UPDATE catalog_sources SET lease_id=$1,lease_until=clock_timestamp()+interval '30 seconds'
 WHERE id=(SELECT id FROM catalog_sources WHERE kind='url' AND NOT paused AND next_fetch_at<=clock_timestamp()
 AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY next_fetch_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
 RETURNING id::text,name,url_ciphertext`, lease).Scan(&id, &name, &ciphertext)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	raw, e := s.Vault.OpenSource(ciphertext, "source-url:"+id)
	var prepared Prepared
	if e == nil {
		prepared, e = s.Prepare(ctx, Input{Name: name, Kind: "url", Input: string(raw)})
		clear(raw)
	}
	return true, s.finishRefresh(ctx, id, lease, prepared, e)
}
func (s *Store) finishRefresh(ctx context.Context, id, lease string, p Prepared, failure error) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer database.Rollback(tx)
	var attempts int
	var current, candidate *string
	var until time.Time
	e = tx.QueryRow(ctx, `SELECT attempts,current_version::text,candidate_version::text,lease_until FROM catalog_sources WHERE id=$1 AND lease_id=$2 AND NOT paused FOR UPDATE`, id, lease).Scan(&attempts, &current, &candidate, &until)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if !until.After(time.Now()) {
		return nil
	}
	code := ""
	outcome := "succeeded"
	if failure != nil {
		code = "source_refresh_failed"
		var safe importer.Error
		if errors.As(failure, &safe) {
			code = string(safe)
		}
		outcome = "failed"
	}
	if failure == nil {
		// A response may have expired during a slow fetch/queue/lock wait.
		p, e = prepare(p.document, time.Now())
		if e != nil {
			code = "source_expired"
			outcome = "failed"
		} else {
			var identical bool
			e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM catalog_versions WHERE source_id=$1 AND id IN ($2::uuid,$3::uuid) AND digest=$4)", id, current, candidate, p.Preview.Digest).Scan(&identical)
			if e != nil {
				return e
			}
			if !identical {
				version, err := s.addVersion(ctx, tx, id, p)
				if errors.Is(err, ErrCapacity) {
					code = "source_capacity"
					outcome = "failed"
				} else if err != nil {
					return err
				} else if _, e = tx.Exec(ctx, "UPDATE catalog_sources SET candidate_version=$2 WHERE id=$1", id, version); e != nil {
					return e
				}
			}
		}
	}
	wait := time.Hour
	attempts = 0
	if code != "" { // bounded exponential retry, retaining the current AND candidate versions
		var old int
		if e = tx.QueryRow(ctx, "SELECT attempts FROM catalog_sources WHERE id=$1", id).Scan(&old); e != nil {
			return e
		}
		attempts = old + 1
		if attempts > 16 {
			attempts = 16
		}
		shift := attempts - 1
		if shift > 6 {
			shift = 6
		}
		wait = time.Minute * time.Duration(1<<shift)
	}
	_, e = tx.Exec(ctx, `UPDATE catalog_sources SET error_code=NULLIF($2,''),attempts=$3,next_fetch_at=clock_timestamp()+$4::bigint*interval '1 second',lease_id=NULL,lease_until=NULL,revision=revision+1,updated_at=clock_timestamp(),paused=paused OR $2='source_capacity' WHERE id=$1`, id, code, attempts, int64(wait.Seconds()))
	if e != nil {
		return e
	}
	if e = audit.Append(ctx, tx, "worker", "source.refreshed", id, outcome); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
