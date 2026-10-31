package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/netip"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"strings"
	"time"
)

type Server struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Address     string    `json:"address"`
	Domain      string    `json:"domain"`
	Connections int       `json:"connections"`
	CreatedAt   time.Time `json:"created_at"`
}
type ServerPage struct {
	Items      []Server `json:"items"`
	NextCursor string   `json:"next_cursor"`
}

// Safe, stable validation codes; never include operator input in error text.
type ServerFieldError string

func (e ServerFieldError) Error() string { return string(e) }
func (e ServerFieldError) Unwrap() error { return ErrInvalid }

func (s *Store) CreateServerTx(ctx context.Context, tx pgx.Tx, m Mutation, name string, addresses ...string) (Server, bool, error) {
	var out Server
	if !validName(name) {
		return out, false, ServerFieldError("server_name_invalid")
	}
	if m.TargetID != "" {
		return out, false, ErrInvalid
	}
	address := ""
	if len(addresses) > 2 {
		return out, false, ErrInvalid
	}
	if len(addresses) >= 1 {
		ip, err := netip.ParseAddr(addresses[0])
		if err != nil || ip.Zone() != "" {
			return out, false, ServerFieldError("server_address_invalid")
		}
		ip = ip.Unmap()
		if ip.IsMulticast() {
			return out, false, ServerFieldError("server_address_multicast")
		}
		if ip.IsUnspecified() {
			return out, false, ServerFieldError("server_address_unspecified")
		}
		address = ip.Unmap().String()
	}
	domain := ""
	if len(addresses) == 2 {
		var err error
		domain, err = canonicalServerDomain(addresses[1])
		if err != nil {
			return out, false, ServerFieldError("server_domain_invalid")
		}
	}
	m.Payload = name
	if address != "" {
		m.Payload = struct{ Name, Address string }{name, address}
	}
	if domain != "" {
		m.Payload = struct{ Name, Address, Domain string }{name, address, domain}
	}
	replay, e := s.mutate(ctx, tx, m, &out, func() error {
		id, e := database.NewID()
		if e != nil {
			return e
		}
		e = tx.QueryRow(ctx, "INSERT INTO infrastructure_servers(id,name,address,domain) VALUES($1,$2,$3,$4) RETURNING id::text,name,address,domain,created_at", id, name, address, domain).Scan(&out.ID, &out.Name, &out.Address, &out.Domain, &out.CreatedAt)
		if e == nil {
			e = audit.Append(ctx, tx, m.ActorID, "infrastructure.server_created", id, "succeeded")
		}
		return e
	})
	return out, replay, e
}
func (s *Store) ServersTx(ctx context.Context, tx pgx.Tx, after string) (ServerPage, error) {
	out := ServerPage{Items: []Server{}}
	if after != "" && !database.ValidID(after) {
		return out, ErrInvalid
	}
	rows, e := tx.Query(ctx, `SELECT s.id::text,s.name,s.address,s.domain,s.created_at,(SELECT count(*) FROM nodes_registry n WHERE n.server_id=s.id AND NOT EXISTS(SELECT 1 FROM server_nodes sn WHERE sn.node_id=n.id)) FROM infrastructure_servers s WHERE ($1='' OR s.id::text>$1) ORDER BY s.id LIMIT 51`, after)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var v Server
		if e = rows.Scan(&v.ID, &v.Name, &v.Address, &v.Domain, &v.CreatedAt, &v.Connections); e != nil {
			return out, e
		}
		out.Items = append(out.Items, v)
	}
	if len(out.Items) > 50 {
		out.Items = out.Items[:50]
		out.NextCursor = out.Items[49].ID
	}
	return out, rows.Err()
}

// Validate only the name here. DNS propagation and ACME readiness are separate
// installation gates, not a reason to lose a saved server or retry its creation.
func canonicalServerDomain(value string) (string, error) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return "", ErrInvalid
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return "", ErrInvalid
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalid
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", ErrInvalid
			}
		}
	}
	return domain, nil
}
func (s *Store) CreateServerConnectionTx(ctx context.Context, tx pgx.Tx, m Mutation, server, name string) (Node, bool, error) {
	if !database.ValidID(server) {
		return Node{}, false, ErrInvalid
	}
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "server-listeners/"+server); e != nil {
		return Node{}, false, e
	}
	var managed bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM server_nodes WHERE server_id=$1)", server).Scan(&managed); e != nil {
		return Node{}, false, e
	}
	if managed {
		return Node{}, false, ErrConflict
	}
	var exists string
	if e := tx.QueryRow(ctx, "SELECT id::text FROM infrastructure_servers WHERE id=$1", server).Scan(&exists); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return Node{}, false, ErrNotFound
		}
		return Node{}, false, e
	}
	n, replay, e := s.CreateTx(ctx, tx, m, name)
	if e != nil {
		return n, replay, e
	}
	// Route includes server ID and is part of the immutable idempotency scope.
	if !replay {
		_, e = tx.Exec(ctx, "UPDATE nodes_registry SET server_id=$2 WHERE id=$1 AND server_id IS NULL", n.ID, server)
	}
	return n, replay, e
}

type ServerNodePage struct {
	Items      []Node `json:"items"`
	NextCursor string `json:"next_cursor"`
}

func (s *Store) ServerConnectionsTx(ctx context.Context, tx pgx.Tx, server, after string) (ServerNodePage, error) {
	out := ServerNodePage{Items: []Node{}}
	if (server != "unassigned" && !database.ValidID(server)) || (after != "" && !database.ValidID(after)) {
		return out, ErrInvalid
	}
	rows, e := tx.Query(ctx, "SELECT "+nodeColumns+" FROM nodes_registry WHERE (($1='unassigned' AND server_id IS NULL) OR server_id::text=$1) AND ($2='' OR id::text>$2) ORDER BY id LIMIT 51", server, after)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		n, e := scanNode(rows)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, n)
	}
	if len(out.Items) > 50 {
		out.Items = out.Items[:50]
		out.NextCursor = out.Items[49].ID
	}
	return out, rows.Err()
}

type VPNConfigVersion struct {
	Revision      int64           `json:"revision"`
	Configuration VPNInstallation `json:"configuration"`
	CreatedAt     time.Time       `json:"created_at"`
}

func (s *Store) VPNHistoryTx(ctx context.Context, tx pgx.Tx, node string, before int64) ([]VPNConfigVersion, error) {
	if !database.ValidID(node) || before < 0 {
		return nil, ErrInvalid
	}
	if s.Vault == nil {
		return nil, ErrKey
	}
	rows, e := tx.Query(ctx, "SELECT revision,body_ciphertext,created_at FROM nodes_vpn_config_versions WHERE node_id=$1 AND ($2::bigint=0 OR revision<$2) ORDER BY revision DESC LIMIT 50", node, before)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []VPNConfigVersion{}
	for rows.Next() {
		var v VPNConfigVersion
		var raw []byte
		if e = rows.Scan(&v.Revision, &raw, &v.CreatedAt); e != nil {
			return nil, e
		}
		plain, e := s.Vault.Open(raw, fmt.Sprintf("node-vpn-version:%s:%d", node, v.Revision))
		if e != nil {
			return nil, ErrKey
		}
		e = json.Unmarshal(plain, &v.Configuration)
		clear(plain)
		if e != nil {
			return nil, ErrKey
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
