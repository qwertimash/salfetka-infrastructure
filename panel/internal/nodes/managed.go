package nodes

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
)

// The existing VPN scope IDs represent logical connections. They have no
// enrollment identity. Only this authorization path delegates to their owner;
// heartbeat, certificate renewal and agent control remain physical-node only.
func (s *Store) lockAuthorizedVPN(ctx context.Context, tx pgx.Tx, cert *x509.Certificate, id string) error {
	var owner *string
	if e := tx.QueryRow(ctx, "SELECT owner_node_id::text FROM nodes_registry WHERE id=$1", id).Scan(&owner); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrUnauthorized
		}
		return e
	}
	if owner == nil {
		return s.lockAuthorizedNode(ctx, tx, cert, id)
	}
	if e := s.lockAuthorizedNode(ctx, tx, cert, *owner); e != nil {
		return e
	}
	var state string
	if e := tx.QueryRow(ctx, "SELECT state FROM nodes_registry WHERE id=$1 AND owner_node_id=$2 FOR UPDATE", id, *owner).Scan(&state); e != nil {
		return e
	}
	if state != "active" {
		return ErrUnauthorized
	}
	return nil
}

// RegisterServerNodeTx reserves one physical identity. Existing per-connection
// agents require an explicit migration, never silent adoption of their services.
func (s *Store) RegisterServerNodeTx(ctx context.Context, tx pgx.Tx, m Mutation, server string) (Node, bool, error) {
	var out Node
	if !database.ValidID(server) || m.TargetID != "" {
		return out, false, ErrInvalid
	}
	m.Payload = server
	replay, e := s.mutate(ctx, tx, m, &out, func() error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "server-listeners/"+server); e != nil {
			return e
		}
		var name string
		if e := tx.QueryRow(ctx, "SELECT name FROM infrastructure_servers WHERE id=$1", server).Scan(&name); e != nil {
			return e
		}
		var exists bool
		if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM nodes_registry WHERE server_id=$1)", server).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return ErrConflict
		}
		id, e := database.NewID()
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO nodes_registry(id,name,server_id) VALUES($1,$2,$3)", id, name, server); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO server_nodes(server_id,node_id) VALUES($1,$2)", server, id); e != nil {
			return e
		}
		if e = audit.Append(ctx, tx, m.ActorID, "node.created", id, "accepted"); e != nil {
			return e
		}
		out, e = s.GetTx(ctx, tx, id)
		return e
	})
	return out, replay, e
}

type ManagedRequest struct {
	Name          string                   `json:"name"`
	Configuration connection.Configuration `json:"configuration"`
	TrustedCAPEM  string                   `json:"trusted_ca_pem,omitempty"`
	GroupID       string                   `json:"group_id"`
	Enabled       bool                     `json:"enabled"`
}
type ManagedConnection struct {
	ID                  string          `json:"id"`
	OwnerNodeID         string          `json:"owner_node_id"`
	Name                string          `json:"name"`
	Revision            int64           `json:"revision"`
	ConfigurationSHA256 string          `json:"configuration_sha256"`
	VPN                 VPNInstallation `json:"vpn"`
}
type ManagedBatch struct {
	NodeRevision int64               `json:"node_revision"`
	Connections  []ManagedConnection `json:"connections"`
}

func managedAAD(id string, revision int64) string {
	return fmt.Sprintf("managed-connection:%s:%d", id, revision)
}

func generateReality(c *connection.Configuration) error {
	if c.Public.Template != connection.Reality {
		return nil
	}
	// Generate a pair only when both were omitted. Never silently replace a key.
	if c.Public.RealityPublicKey == "" && c.Private.RealityPrivateKey == "" {
		key, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		c.Private.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
		c.Public.RealityPublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	if c.Public.RealityShortID == "" {
		var b [8]byte
		if _, e := rand.Read(b[:]); e != nil {
			return e
		}
		c.Public.RealityShortID = hex.EncodeToString(b[:])
	}
	return nil
}

func (s *Store) CreateManagedConnectionsTx(ctx context.Context, tx pgx.Tx, m Mutation, requests []ManagedRequest) (ManagedBatch, bool, error) {
	var out ManagedBatch
	if !database.ValidID(m.TargetID) || len(requests) < 1 || len(requests) > 32 {
		return out, false, ErrInvalid
	}
	for _, r := range requests {
		if !validName(r.Name) || !database.ValidID(r.GroupID) {
			return out, false, ErrInvalid
		}
	}
	m.Payload = requests
	replay, e := s.mutate(ctx, tx, m, &out, func() error {
		var server, state string
		if e := tx.QueryRow(ctx, "SELECT s.server_id::text,n.state FROM server_nodes s JOIN nodes_registry n ON n.id=s.node_id WHERE s.node_id=$1", m.TargetID).Scan(&server, &state); e != nil {
			return e
		}
		if state == "revoked" {
			return ErrConflict
		}
		var total int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM nodes_registry WHERE owner_node_id=$1", m.TargetID).Scan(&total); e != nil {
			return e
		}
		if total+len(requests) > 256 {
			return ErrVPNCapacity
		}
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "server-listeners/"+server); e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT v.endpoint FROM nodes_vpn_installations v JOIN nodes_registry n ON n.id=v.node_id WHERE n.server_id=$1 AND n.state<>'revoked'`, server)
		if e != nil {
			return e
		}
		occupied := []connection.Listener{}
		count := 0
		for rows.Next() {
			count++
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return e
			}
			var ep VPNEndpoint
			if json.Unmarshal(raw, &ep) != nil || !ep.Valid() {
				rows.Close()
				return ErrConflict
			}
			if ep.Backend == "olcrtc" {
				continue
			}
			ip, network := "::", "tcp"
			if ep.Connection != nil {
				ip = ep.Connection.ListenIP
			}
			if ep.Backend == "hysteria2" {
				network = "udp"
			}
			occupied = append(occupied, connection.Listener{IP: ip, Port: ep.Port, Network: network})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if count+len(requests) > 32 {
			return ErrVPNCapacity
		}
		configs := make([]connection.Configuration, len(requests))
		wanted := make([]connection.Spec, len(requests))
		for i, r := range requests {
			configs[i] = r.Configuration
			if e = generateReality(&configs[i]); e != nil {
				return e
			}
			wanted[i] = configs[i].Public
		}
		allocated, e := connection.Allocate(wanted, occupied)
		if e != nil {
			return ErrInvalid
		}
		out.Connections = []ManagedConnection{}
		for i, r := range requests {
			c := configs[i]
			c.Public = allocated[i]
			if c.Validate() != nil {
				return ErrInvalid
			}
			id, e := database.NewID()
			if e != nil {
				return e
			}
			installation, e := database.NewID()
			if e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, "INSERT INTO nodes_registry(id,name,state,server_id,owner_node_id) VALUES($1,$2,'active',$3,$4)", id, r.Name, server, m.TargetID); e != nil {
				return e
			}
			ep := VPNEndpoint{Connection: &c.Public, Host: c.Public.Host, Port: c.Public.Port, ServerName: c.Public.ServerName, TrustedCAPEM: r.TrustedCAPEM}
			if c.Public.Template == connection.Hy2 {
				ep.Backend = "hysteria2"
			}
			vpn, _, e := s.configureVPNTx(ctx, tx, Mutation{ActorID: m.ActorID, Route: "managed.internal", TargetID: id, Key: id, Revision: 1}, installation, r.GroupID, r.Enabled, true, &ep)
			if e != nil {
				return e
			}
			raw, e := json.Marshal(c)
			if e != nil {
				return e
			}
			sealed, e := s.Vault.Seal(raw, managedAAD(id, 1))
			clear(raw)
			if e != nil {
				return ErrKey
			}
			hash := connection.Hash(c)
			if _, e = tx.Exec(ctx, "INSERT INTO managed_connection_versions(connection_id,revision,configuration_ciphertext,configuration_sha256,trusted_ca_pem) VALUES($1,1,$2,$3,$4)", id, sealed, hash, r.TrustedCAPEM); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, "INSERT INTO managed_connections(connection_id,revision) VALUES($1,1)", id); e != nil {
				return e
			}
			out.Connections = append(out.Connections, ManagedConnection{ID: id, OwnerNodeID: m.TargetID, Name: r.Name, Revision: 1, ConfigurationSHA256: hash, VPN: vpn})
		}
		if _, e = tx.Exec(ctx, "UPDATE server_nodes SET revision=revision+1 WHERE node_id=$1", m.TargetID); e != nil {
			return e
		}
		return tx.QueryRow(ctx, "UPDATE nodes_registry SET revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision", m.TargetID).Scan(&out.NodeRevision)
	})
	return out, replay, e
}
