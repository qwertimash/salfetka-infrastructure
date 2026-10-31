// Package roomroute stores admission-bound routing, never client authentication.
package roomroute

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

const MaxRooms = 100

var ErrCapacity = errors.New("room_capacity")
var ErrInvalid = errors.New("room_route_invalid")

// Reserve is called only in the authorized subscription-stage transaction, after
// node then user locks. Persisting a route admits its account to this installation.
// Slots are deliberately durable; no TTL may recycle a still-published room.
func Reserve(ctx context.Context, tx pgx.Tx, installation, user string) (string, error) {
	if !database.ValidID(installation) || !database.ValidID(user) {
		return "", ErrInvalid
	}
	// Separate reservation lock also serializes callers holding shared node locks.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,74))", installation); err != nil {
		return "", err
	}
	var room string
	err := tx.QueryRow(ctx, "SELECT room_id FROM account_rooms WHERE installation_id=$1 AND user_id=$2", installation, user).Scan(&room)
	if err == nil {
		return room, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	var n int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM account_rooms WHERE installation_id=$1", installation).Scan(&n); err != nil {
		return "", err
	}
	if n >= MaxRooms {
		return "", ErrCapacity
	}
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", ErrInvalid
	}
	room = hex.EncodeToString(b[:])
	_, err = tx.Exec(ctx, "INSERT INTO account_rooms(installation_id,user_id,room_id) VALUES($1,$2,$3)", installation, user, room)
	return room, err
}
func Lookup(ctx context.Context, tx pgx.Tx, installation, user string) (string, error) {
	var room string
	err := tx.QueryRow(ctx, "SELECT room_id FROM account_rooms WHERE installation_id=$1 AND user_id=$2", installation, user).Scan(&room)
	return room, err
}

// URL replaces only the final room component, preserving the configured provider
// base path. Query/fragment credentials are forbidden in this capability.
func URL(base, room string) (string, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !nodewire.ValidOLCKey(room) {
		return "", ErrInvalid
	}
	u.Path = strings.TrimRight(u.Path, "/")
	i := strings.LastIndex(u.Path, "/")
	if i < 0 {
		u.Path = "/" + room
	} else {
		u.Path = u.Path[:i+1] + room
	}
	u.RawPath = ""
	return u.String(), nil
}
