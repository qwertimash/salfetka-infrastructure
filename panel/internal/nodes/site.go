package nodes

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
	"strings"
	"time"
)

func validSite(r *nodewire.SiteStatus, now time.Time) bool {
	if r == nil {
		return true
	}
	domain, err := canonicalServerDomain(r.Domain)
	if err != nil || domain != r.Domain {
		return false
	}
	if r.State == "unavailable" {
		return r.CertificatePEM == "" && r.ExpiresAt.IsZero()
	}
	if r.State != "ready" || len(r.CertificatePEM) > 32768 {
		return false
	}
	raw := []byte(r.CertificatePEM)
	count := 0
	for len(strings.TrimSpace(string(raw))) > 0 {
		if !strings.HasPrefix(strings.TrimSpace(string(raw)), "-----BEGIN CERTIFICATE-----") {
			return false
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}
		if count == 0 && (cert.VerifyHostname(domain) != nil || !r.ExpiresAt.Equal(cert.NotAfter) || (!now.IsZero() && (now.Before(cert.NotBefore) || !now.Before(cert.NotAfter)))) {
			return false
		}
		count++
		raw = rest
	}
	return count > 0 && count <= 8
}

// SiteInfo cannot be read with an invitation, a browser cookie, or another
// node's certificate. It reveals only this identity's own immutable server fields.
func (s *Store) SiteInfo(ctx context.Context, cert *x509.Certificate, id string) (nodewire.SiteInfo, error) {
	out := nodewire.SiteInfo{SchemaVersion: 1, NodeID: id}
	if !database.ValidID(id) {
		return out, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer database.Rollback(tx)
	if err = s.lockAuthorizedNode(ctx, tx, cert, id); err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, `SELECT i.domain,i.address FROM infrastructure_servers i JOIN server_nodes n ON n.server_id=i.id WHERE n.node_id=$1`, id).Scan(&out.Domain, &out.Address)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) validateSiteOwner(ctx context.Context, tx pgx.Tx, id string, site *nodewire.SiteStatus) error {
	if site == nil {
		return nil
	}
	var domain string
	err := tx.QueryRow(ctx, `SELECT i.domain FROM infrastructure_servers i JOIN server_nodes n ON n.server_id=i.id WHERE n.node_id=$1`, id).Scan(&domain)
	if err != nil || domain != site.Domain {
		return ErrInvalid
	}
	return nil
}

func (s *Store) nodeCertificateReady(ctx context.Context, tx pgx.Tx, id string, c connection.Configuration, trust string, enabled bool) error {
	if c.Public.CertificateSource != "node" {
		return nil
	}
	if trust != "" {
		return ErrInvalid
	} // Public ACME clients use system trust, never pin a rotating leaf.
	// Disabling must remain possible during certificate/website failure.
	if !enabled {
		return nil
	}
	var raw []byte
	var domain string
	var seen, now time.Time
	err := tx.QueryRow(ctx, `SELECT i.domain,n.inventory->'site',n.last_seen_at,clock_timestamp() FROM nodes_registry n JOIN server_nodes sn ON sn.node_id=n.id JOIN infrastructure_servers i ON i.id=sn.server_id WHERE n.id=$1 AND n.state='active'`, id).Scan(&domain, &raw, &seen, &now)
	if err != nil || domain != c.Public.ServerName || !seen.After(now.Add(-45*time.Second)) {
		return ErrConflict
	}
	var status nodewire.SiteStatus
	if json.Unmarshal(raw, &status) != nil || status.Domain != domain || status.State != "ready" || !validSite(&status, now) {
		return ErrConflict
	}
	// The site's ports are reserved and must never be allocated to a VPN listener.
	if c.Public.Network() == "tcp" && (c.Public.Port == 80 || c.Public.Port == 8445) {
		return ErrInvalid
	}
	return nil
}
