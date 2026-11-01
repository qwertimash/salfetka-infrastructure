package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodewire"
	"time"
)

type ManagedDetail struct {
	ManagedConnection
	RuntimeState string    `json:"runtime_state"`
	ErrorCode    string    `json:"error_code,omitempty"`
	Traffic      VPNStatus `json:"traffic"`
}
type ManagedServer struct {
	Node        *Node           `json:"node"`
	Legacy      bool            `json:"legacy"`
	Connections []ManagedDetail `json:"connections"`
}

func (s *Store) ManagedServerTx(ctx context.Context, tx pgx.Tx, server string) (ManagedServer, error) {
	out := ManagedServer{Connections: []ManagedDetail{}}
	if !database.ValidID(server) {
		return out, ErrInvalid
	}
	var id string
	var revision int64
	e := tx.QueryRow(ctx, "SELECT node_id::text,revision FROM server_nodes WHERE server_id=$1", server).Scan(&id, &revision)
	if errors.Is(e, pgx.ErrNoRows) {
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM nodes_registry WHERE server_id=$1)", server).Scan(&out.Legacy)
		return out, e
	}
	if e != nil {
		return out, e
	}
	node, e := s.GetTx(ctx, tx, id)
	if e != nil {
		return out, e
	}
	out.Node = &node
	rows, e := tx.Query(ctx, `SELECT n.id::text,n.name,m.revision,v.configuration_sha256 FROM nodes_registry n JOIN managed_connections m ON m.connection_id=n.id JOIN managed_connection_versions v ON v.connection_id=m.connection_id AND v.revision=m.revision WHERE n.owner_node_id=$1 AND n.state<>'revoked' ORDER BY n.id`, id)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		c := ManagedDetail{ManagedConnection: ManagedConnection{OwnerNodeID: id}, RuntimeState: "pending"}
		if e = rows.Scan(&c.ID, &c.Name, &c.Revision, &c.ConfigurationSHA256); e != nil {
			rows.Close()
			return out, e
		}
		out.Connections = append(out.Connections, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	var body []byte
	var received, now time.Time
	var observedRevision int64
	e = tx.QueryRow(ctx, "SELECT body,received_at,clock_timestamp(),plan_revision FROM managed_connection_observations WHERE node_id=$1", id).Scan(&body, &received, &now, &observedRevision)
	states := map[string]nodewire.ConnectionState{}
	if e == nil && observedRevision == revision && received.After(now.Add(-25*time.Second)) && node.ContactState == "fresh" {
		var r nodewire.ConnectionsReport
		if json.Unmarshal(body, &r) != nil {
			return out, ErrInvalid
		}
		if node.Inventory != nil && r.BootID == node.Inventory.BootID {
			for _, st := range r.States {
				states[st.ID] = st
			}
		}
	} else if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	for i := range out.Connections {
		c := &out.Connections[i]
		status, e := s.VPNStatusTx(ctx, tx, c.ID)
		if e != nil {
			return out, e
		}
		c.Traffic = status
		if status.Installation != nil {
			c.VPN = *status.Installation
		}
		if st, ok := states[c.ID]; ok && st.Revision == c.Revision {
			c.RuntimeState = st.State
			c.ErrorCode = st.ErrorCode
		}
	}
	return out, nil
}

type ManagedUpdate struct {
	Request          ManagedRequest `json:"request"`
	ReplacePrivate   bool           `json:"replace_private"`
	RollbackRevision int64          `json:"rollback_revision,omitempty"`
}

func (s *Store) UpdateManagedConnectionTx(ctx context.Context, tx pgx.Tx, m Mutation, u ManagedUpdate) (ManagedConnection, bool, error) {
	var out ManagedConnection
	if !database.ValidID(m.TargetID) {
		return out, false, ErrInvalid
	}
	m.Payload = u
	replay, e := s.mutate(ctx, tx, m, &out, func() error {
		var owner, name string
		var revision int64
		var ciphertext []byte
		e := tx.QueryRow(ctx, `SELECT n.owner_node_id::text,n.name,m.revision,v.configuration_ciphertext FROM nodes_registry n JOIN managed_connections m ON m.connection_id=n.id JOIN managed_connection_versions v ON v.connection_id=m.connection_id AND v.revision=m.revision JOIN nodes_registry p ON p.id=n.owner_node_id WHERE n.id=$1 AND n.state='active' AND p.state<>'revoked'`, m.TargetID).Scan(&owner, &name, &revision, &ciphertext)
		if e != nil {
			return e
		}
		plain, e := s.Vault.Open(ciphertext, managedAAD(m.TargetID, revision))
		if e != nil {
			return ErrKey
		}
		var old connection.Configuration
		e = json.Unmarshal(plain, &old)
		clear(plain)
		if e != nil {
			return ErrKey
		}
		status, e := s.VPNStatusTx(ctx, tx, m.TargetID)
		if e != nil {
			return e
		}
		if status.Installation == nil {
			return ErrConflict
		}
		v := status.Installation
		request := u.Request
		if u.RollbackRevision > 0 {
			if u.ReplacePrivate {
				return ErrInvalid
			}
			if e = tx.QueryRow(ctx, "SELECT configuration_ciphertext,trusted_ca_pem FROM managed_connection_versions WHERE connection_id=$1 AND revision=$2", m.TargetID, u.RollbackRevision).Scan(&ciphertext, &request.TrustedCAPEM); e != nil {
				return e
			}
			plain, e = s.Vault.Open(ciphertext, managedAAD(m.TargetID, u.RollbackRevision))
			if e != nil {
				return ErrKey
			}
			e = json.Unmarshal(plain, &request.Configuration)
			clear(plain)
			if e != nil {
				return ErrKey
			}
			// Rollback changes configuration, never re-enables access or restores grants.
			request.Name = name
			request.GroupID = v.GroupID
			request.Enabled = v.Enabled
		} else if !u.ReplacePrivate {
			if request.Configuration.Private != (connection.PrivateMaterial{}) {
				return ErrInvalid
			}
			request.Configuration.Private = old.Private
		}
		c := request.Configuration
		if e = s.nodeCertificateReady(ctx, tx, owner, c, request.TrustedCAPEM, request.Enabled); e != nil {
			return e
		}
		if c.Public.Template != old.Public.Template || c.Validate() != nil || !validName(request.Name) {
			return ErrInvalid
		}
		ep := VPNEndpoint{Backend: v.Endpoint.Backend, Connection: &c.Public, Host: c.Public.Host, Port: c.Public.Port, ServerName: c.Public.ServerName, TrustedCAPEM: request.TrustedCAPEM}
		vpn, _, e := s.configureVPNTx(ctx, tx, Mutation{ActorID: m.ActorID, Route: "managed.update.internal", TargetID: m.TargetID, Key: m.Key, Revision: m.Revision}, v.InstallationID, request.GroupID, request.Enabled, true, &ep)
		if e != nil {
			return e
		}
		revision++
		raw, _ := json.Marshal(c)
		ciphertext, e = s.Vault.Seal(raw, managedAAD(m.TargetID, revision))
		clear(raw)
		if e != nil {
			return ErrKey
		}
		hash := connection.Hash(c)
		if _, e = tx.Exec(ctx, "INSERT INTO managed_connection_versions(connection_id,revision,configuration_ciphertext,configuration_sha256,trusted_ca_pem) VALUES($1,$2,$3,$4,$5)", m.TargetID, revision, ciphertext, hash, request.TrustedCAPEM); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE managed_connections SET revision=$2 WHERE connection_id=$1", m.TargetID, revision); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE nodes_registry SET name=$2 WHERE id=$1", m.TargetID, request.Name); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE server_nodes SET revision=revision+1 WHERE node_id=$1", owner); e != nil {
			return e
		}
		out = ManagedConnection{ID: m.TargetID, OwnerNodeID: owner, Name: request.Name, Revision: revision, ConfigurationSHA256: hash, VPN: vpn}
		return nil
	})
	return out, replay, e
}

type ManagedVersion struct {
	Revision  int64           `json:"revision"`
	Public    connection.Spec `json:"public"`
	CreatedAt time.Time       `json:"created_at"`
}

func (s *Store) ManagedHistoryTx(ctx context.Context, tx pgx.Tx, id string) ([]ManagedVersion, error) {
	if !database.ValidID(id) {
		return nil, ErrInvalid
	}
	if s.Vault == nil {
		return nil, ErrKey
	}
	rows, e := tx.Query(ctx, "SELECT revision,configuration_ciphertext,created_at FROM managed_connection_versions WHERE connection_id=$1 ORDER BY revision DESC LIMIT 50", id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ManagedVersion{}
	for rows.Next() {
		var v ManagedVersion
		var ciphertext []byte
		if e = rows.Scan(&v.Revision, &ciphertext, &v.CreatedAt); e != nil {
			return nil, e
		}
		plain, e := s.Vault.Open(ciphertext, managedAAD(id, v.Revision))
		if e != nil {
			return nil, ErrKey
		}
		var c connection.Configuration
		e = json.Unmarshal(plain, &c)
		clear(plain)
		if e != nil {
			return nil, ErrKey
		}
		v.Public = c.Public
		out = append(out, v)
	}
	return out, rows.Err()
}
