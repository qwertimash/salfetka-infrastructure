package nodes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

// Called only after locking the active node and checking its key. An old
// certificate is accepted through its original expiry, never through renewal's.
func (s *Store) serialAuthorized(ctx context.Context, tx pgx.Tx, id string, cert *x509.Certificate, current *string, expires *time.Time, now time.Time) (bool, error) {
	if current == nil || expires == nil || !now.Before(cert.NotAfter) || now.Before(cert.NotBefore) {
		return false, nil
	}
	serial := cert.SerialNumber.Text(16)
	if *current == serial {
		return expires.After(now) && expires.Equal(cert.NotAfter), nil
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes_certificate_renewals WHERE node_id=$1 AND previous_serial=$2 AND previous_expires_at=$3 AND previous_expires_at>$4)`, id, serial, cert.NotAfter, now).Scan(&ok)
	return ok, err
}

func (s *Store) Renew(ctx context.Context, cert *x509.Certificate, r nodewire.RenewalRequest) (nodewire.EnrollmentResponse, bool, error) {
	var out nodewire.EnrollmentResponse
	if r.SchemaVersion != 1 || !database.ValidID(r.NodeID) || cert == nil || r.PreviousSerial != cert.SerialNumber.Text(16) {
		return out, false, ErrInvalid
	}
	csr, err := parseCSR(r.CSRPEM)
	if err != nil {
		return out, false, err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(csr.PublicKey.(ed25519.PublicKey), pub) {
		return out, false, ErrProof
	}
	hash := sha256.Sum256([]byte(r.CSRPEM))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer database.Rollback(tx)
	if err = s.lockAuthorizedNode(ctx, tx, cert, r.NodeID); err != nil {
		return out, false, err
	}
	var storedHash []byte
	var raw string
	err = tx.QueryRow(ctx, "SELECT csr_hash,response FROM nodes_certificate_renewals WHERE node_id=$1 AND previous_serial=$2", r.NodeID, r.PreviousSerial).Scan(&storedHash, &raw)
	if err == nil {
		if !bytes.Equal(hash[:], storedHash) {
			return out, false, ErrConflict
		}
		if err = json.Unmarshal([]byte(raw), &out); err != nil {
			return out, false, err
		}
		return out, true, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, false, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return out, false, err
	}
	if cert.NotAfter.Sub(now) > 8*time.Hour {
		return out, false, ErrConflict
	}
	out, err = s.Authority.issue(r.NodeID, csr, now)
	if err != nil {
		return out, false, err
	}
	if !out.ExpiresAt.After(cert.NotAfter) {
		return out, false, ErrAuthority
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO nodes_certificate_renewals(node_id,previous_serial,previous_expires_at,serial,expires_at,csr_hash,response) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.NodeID, r.PreviousSerial, cert.NotAfter, out.Serial, out.ExpiresAt, hash[:], string(encoded)); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE nodes_registry SET serial=$2,certificate_expires_at=$3,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1`, r.NodeID, out.Serial, out.ExpiresAt); err != nil {
		return out, false, err
	}
	if err = audit.Append(ctx, tx, r.NodeID, "node.certificate_renewed", r.NodeID, "succeeded"); err != nil {
		return out, false, err
	}
	return out, false, tx.Commit(ctx)
}
