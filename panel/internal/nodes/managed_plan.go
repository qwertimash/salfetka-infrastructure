package nodes

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
)

// ConnectionsDesired discloses private configuration only over authenticated
// mTLS to its single owner, never in an operator list/preview response.
func (s *Store) ConnectionsDesired(ctx context.Context, cert *x509.Certificate, id string) (nodewire.SignedConnectionsPlan, error) {
	var out nodewire.SignedConnectionsPlan
	if !database.ValidID(id) {
		return out, ErrInvalid
	}
	if s.Vault == nil || s.Signer == nil {
		return out, ErrKey
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer database.Rollback(tx)
	if e = s.lockAuthorizedNode(ctx, tx, cert, id); e != nil {
		return out, e
	}
	var capable bool
	if e = tx.QueryRow(ctx, "SELECT coalesce(inventory->'capabilities' ? 'managed_connections_v1',false) FROM nodes_registry WHERE id=$1", id).Scan(&capable); e != nil {
		return out, e
	}
	if !capable {
		return out, ErrConflict
	}
	plan := nodewire.ConnectionsPlan{SchemaVersion: 1, NodeID: id, Connections: []nodewire.ConnectionDeployment{}}
	if e = tx.QueryRow(ctx, "SELECT revision,date_trunc('second',clock_timestamp()),date_trunc('second',clock_timestamp())+interval '5 minutes' FROM server_nodes WHERE node_id=$1", id).Scan(&plan.Revision, &plan.IssuedAt, &plan.ExpiresAt); e != nil {
		return out, e
	}
	rows, e := tx.Query(ctx, `SELECT n.id::text,m.revision,v.configuration_ciphertext,v.configuration_sha256,i.installation_id::text,i.enabled FROM nodes_registry n JOIN managed_connections m ON m.connection_id=n.id JOIN managed_connection_versions v ON v.connection_id=m.connection_id AND v.revision=m.revision JOIN nodes_vpn_installations i ON i.node_id=n.id WHERE n.owner_node_id=$1 AND n.state='active' ORDER BY n.id`, id)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var c nodewire.ConnectionDeployment
		var raw []byte
		if e = rows.Scan(&c.ID, &c.Revision, &raw, &c.ConfigurationSHA256, &c.InstallationID, &c.Enabled); e != nil {
			rows.Close()
			return out, e
		}
		plain, e := s.Vault.Open(raw, managedAAD(c.ID, c.Revision))
		if e != nil {
			rows.Close()
			return out, ErrKey
		}
		e = json.Unmarshal(plain, &c.Configuration)
		clear(plain)
		if e != nil || c.Configuration.Validate() != nil || connection.Hash(c.Configuration) != c.ConfigurationSHA256 {
			rows.Close()
			return out, ErrKey
		}
		plan.Connections = append(plan.Connections, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	out, e = s.Signer.SignConnections(plan)
	if e != nil {
		return out, ErrInvalid
	}
	e = tx.Commit(ctx)
	return out, e
}
