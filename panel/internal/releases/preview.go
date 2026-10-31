package releases

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"time"
)

type Preview struct {
	Candidate     compiler.Layout  `json:"candidate"`
	Current       *compiler.Layout `json:"current"`
	UserID        string           `json:"user_id"`
	DeviceID      string           `json:"device_id"`
	NodeIDs       []string         `json:"node_ids"`
	AccessChanged bool             `json:"access_changed"`
	ServerRestart bool             `json:"server_restart"`
	Checks        []Check          `json:"checks"`
}

func (s *Store) PreviewTx(ctx context.Context, tx pgx.Tx, user, device, release string) (Preview, error) {
	out := Preview{UserID: user, DeviceID: device}
	if !database.ValidID(user) || !database.ValidID(device) || !database.ValidID(release) {
		return out, ErrInvalid
	}
	d, e := s.DetailTx(ctx, tx, user, device)
	if e != nil {
		return out, e
	}
	var found *Release
	for _, r := range d.Releases {
		if r.ID == release {
			x := r
			found = &x
		}
	}
	if found == nil {
		return out, ErrInvalid
	}
	out.Checks = found.Checks
	var provenance struct {
		NodeIDs []string `json:"node_ids"`
	}
	json.Unmarshal(found.Provenance, &provenance)
	out.NodeIDs = provenance.NodeIDs
	read := func(id string) (compiler.Layout, error) {
		var cipher []byte
		if e := tx.QueryRow(ctx, "SELECT artifact_ciphertext FROM subscription_releases WHERE subscription_id=$1 AND id=$2", d.Subscription.ID, id).Scan(&cipher); e != nil {
			return compiler.Layout{}, e
		}
		b, e := s.Vault.OpenSource(cipher, "release-artifact:"+d.Subscription.ID+":"+id)
		if e != nil {
			return compiler.Layout{}, e
		}
		defer clear(b)
		// A historical preview describes its frozen artifact, even after its lease
		// expires. It grants no delivery permission and cannot publish by itself.
		var created time.Time
		if e = tx.QueryRow(ctx, "SELECT created_at FROM subscription_releases WHERE id=$1", id).Scan(&created); e != nil {
			return compiler.Layout{}, e
		}
		return compiler.Present(b, created.Add(-time.Second))
	}
	out.Candidate, e = read(release)
	if e != nil {
		return out, e
	}
	if d.Subscription.ActiveRelease != nil {
		v, e := read(*d.Subscription.ActiveRelease)
		if e != nil {
			return out, e
		}
		out.Current = &v
	}
	return out, nil
}
