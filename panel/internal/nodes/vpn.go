package nodes

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
)

type VPNInstallation struct {
	NodeID         string       `json:"node_id"`
	InstallationID string       `json:"installation_id"`
	GroupID        string       `json:"group_id"`
	Enabled        bool         `json:"enabled"`
	NodeRevision   int64        `json:"node_revision"`
	Endpoint       *VPNEndpoint `json:"endpoint"`
}
type VPNFetch = nodewire.VPNFetch

var engineEpochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var ErrVPNCapacity = errors.New("node_vpn_capacity")

// ConfigureVPNTx is for the existing authorized node-write transaction. It does
// not authorize callers itself; public HTTP wiring is a separate B4 batch.
func (s *Store) ConfigureVPNTx(ctx context.Context, tx pgx.Tx, m Mutation, installationID, groupID string, enabled bool, endpoints ...*VPNEndpoint) (VPNInstallation, bool, error) {
	return s.configureVPNTx(ctx, tx, m, installationID, groupID, enabled, false, endpoints...)
}
func (s *Store) configureVPNTx(ctx context.Context, tx pgx.Tx, m Mutation, installationID, groupID string, enabled, managed bool, endpoints ...*VPNEndpoint) (VPNInstallation, bool, error) {
	var out VPNInstallation
	if !database.ValidID(m.TargetID) || !database.ValidID(installationID) || !database.ValidID(groupID) || m.Revision < 1 {
		return out, false, ErrInvalid
	}
	var endpoint *VPNEndpoint
	if len(endpoints) > 1 {
		return out, false, ErrInvalid
	}
	if len(endpoints) == 1 {
		endpoint = endpoints[0]
	}
	if endpoint != nil && (!endpoint.Valid() || (endpoint.Connection != nil && !managed)) {
		return out, false, ErrInvalid
	}
	m.Payload = struct {
		InstallationID, GroupID string
		Enabled                 bool
		Endpoint                *VPNEndpoint
	}{installationID, groupID, enabled, endpoint}
	replay, err := s.mutate(ctx, tx, m, &out, func() error {
		var state string
		var owner *string
		if err := tx.QueryRow(ctx, "SELECT state,owner_node_id::text FROM nodes_registry WHERE id=$1", m.TargetID).Scan(&state, &owner); err != nil {
			return err
		}
		if state != "active" || ((owner != nil) != managed) {
			return ErrConflict
		}
		var present bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM access_groups WHERE id=$1)", groupID).Scan(&present); err != nil {
			return err
		}
		if !present {
			return ErrInvalid
		}
		if endpoint != nil && endpoint.Backend != "olcrtc" {
			var server *string
			if e := tx.QueryRow(ctx, "SELECT server_id::text FROM nodes_registry WHERE id=$1", m.TargetID).Scan(&server); e != nil {
				return e
			}
			if server != nil {
				// Serialize listener allocation without granting UPDATE on the
				// immutable server directory to the runtime DB role.
				if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "server-listeners/"+*server); e != nil {
					return e
				}
				rows, e := tx.Query(ctx, `SELECT v.endpoint FROM nodes_vpn_installations v JOIN nodes_registry n ON n.id=v.node_id WHERE n.server_id=$1 AND n.id<>$2 AND n.state<>'revoked'`, *server, m.TargetID)
				if e != nil {
					return e
				}
				desired := connection.Listener{IP: "::", Port: endpoint.Port, Network: "tcp"}
				if endpoint.Backend == "hysteria2" {
					desired.Network = "udp"
				}
				if endpoint.Connection != nil {
					desired.IP = endpoint.Connection.ListenIP
				}
				conflict := false
				for rows.Next() {
					var raw []byte
					if e = rows.Scan(&raw); e != nil {
						rows.Close()
						return e
					}
					var other *VPNEndpoint
					if json.Unmarshal(raw, &other) != nil || other == nil || other.Backend == "olcrtc" {
						continue
					}
					occupied := connection.Listener{IP: "::", Port: other.Port, Network: "tcp"}
					if other.Backend == "hysteria2" {
						occupied.Network = "udp"
					}
					if other.Connection != nil {
						occupied.IP = other.Connection.ListenIP
					}
					if connection.Conflicts(desired, occupied) {
						conflict = true
					}
				}
				e = rows.Err()
				rows.Close()
				if e != nil {
					return e
				}
				if conflict {
					return ErrConflict
				}
			}
		}
		var oldJSON []byte
		e := tx.QueryRow(ctx, "SELECT endpoint FROM nodes_vpn_installations WHERE node_id=$1", m.TargetID).Scan(&oldJSON)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if e == nil && endpoint != nil {
			var old *VPNEndpoint
			if len(oldJSON) > 0 && json.Unmarshal(oldJSON, &old) != nil {
				return ErrInvalid
			}
			prior := ""
			if old != nil {
				prior = old.Backend
			}
			if prior != endpoint.Backend {
				return ErrConflict
			}
		}
		var bound string
		err := tx.QueryRow(ctx, `INSERT INTO nodes_vpn_installations(node_id,installation_id,group_id,enabled) VALUES($1,$2,$3,$4) ON CONFLICT(node_id) DO UPDATE SET group_id=excluded.group_id,enabled=excluded.enabled,projection_sha256=NULL,updated_at=clock_timestamp() WHERE nodes_vpn_installations.installation_id=excluded.installation_id RETURNING installation_id::text`, m.TargetID, installationID, groupID, enabled).Scan(&bound)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if endpoint != nil {
			encoded, _ := json.Marshal(endpoint)
			if _, err = tx.Exec(ctx, "UPDATE nodes_vpn_installations SET endpoint=$2::jsonb WHERE node_id=$1", m.TargetID, string(encoded)); err != nil {
				return err
			}
		}
		var saved *VPNEndpoint
		var endpointJSON []byte
		if err = tx.QueryRow(ctx, "SELECT endpoint FROM nodes_vpn_installations WHERE node_id=$1", m.TargetID).Scan(&endpointJSON); err != nil {
			return err
		}
		if endpointJSON != nil && json.Unmarshal(endpointJSON, &saved) != nil {
			return ErrInvalid
		}
		var revision int64
		if err = tx.QueryRow(ctx, "UPDATE nodes_registry SET revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision", m.TargetID).Scan(&revision); err != nil {
			return err
		}
		out = VPNInstallation{m.TargetID, bound, groupID, enabled, revision, saved}
		encoded, e := json.Marshal(out)
		if e != nil {
			return e
		}
		ciphertext, e := s.Vault.Seal(encoded, fmt.Sprintf("node-vpn-version:%s:%d", m.TargetID, revision))
		clear(encoded)
		if e != nil {
			return ErrKey
		}
		if _, e = tx.Exec(ctx, "INSERT INTO nodes_vpn_config_versions(node_id,revision,body_ciphertext) VALUES($1,$2,$3)", m.TargetID, revision, ciphertext); e != nil {
			return e
		}
		return audit.Append(ctx, tx, m.ActorID, "node.vpn_configured", m.TargetID, "accepted")
	})
	return out, replay, err
}
func vpnAAD(node, installation, epoch string, generation int64) string {
	return fmt.Sprintf("vpn:%s:%s:%s:%d", node, installation, epoch, generation)
}
func projectionHash(grants []nodewire.VPNGrant, leaseEnd time.Time, group string, enabled bool) string {
	copyGrants := make([]nodewire.VPNGrant, len(grants))
	copy(copyGrants, grants)
	for i := range copyGrants {
		copyGrants[i].Generation = 0
		if copyGrants[i].ExpiresAt.Equal(leaseEnd) {
			copyGrants[i].ExpiresAt = time.Time{}
		}
	}
	raw, _ := json.Marshal(struct {
		Group   string
		Enabled bool
		Grants  []nodewire.VPNGrant
	}{group, enabled, copyGrants})
	sum := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(sum[:])
}

// VPNDesired authenticates the live node on EVERY request and serializes issuance.
// Response retries preserve the exact signed bytes/deadline. A new engine epoch,
// policy change or renewal window creates a new monotonic generation atomically.
func (s *Store) VPNDesired(ctx context.Context, cert *x509.Certificate, request VPNFetch) (nodewire.VPNDesired, bool, error) {
	out := nodewire.VPNDesired{SchemaVersion: 1, NodeID: request.NodeID}
	if !nodewire.ValidBackend(request.Backend) || request.SchemaVersion != 1 || !database.ValidID(request.NodeID) || !database.ValidID(request.InstallationID) || !engineEpochPattern.MatchString(request.EngineEpoch) {
		return out, false, ErrInvalid
	}
	if s.Vault == nil || s.Signer == nil {
		return out, false, ErrKey
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer database.Rollback(tx)
	if err = s.lockAuthorizedVPN(ctx, tx, cert, request.NodeID); err != nil {
		return out, false, err
	}
	var installation, group string
	var enabled bool
	var generation int64
	var epoch, projection *string
	var currentExpiry *time.Time
	err = tx.QueryRow(ctx, `SELECT installation_id::text,group_id::text,enabled,generation,engine_epoch,projection_sha256,policy_expires_at FROM nodes_vpn_installations WHERE node_id=$1 FOR UPDATE`, request.NodeID).Scan(&installation, &group, &enabled, &generation, &epoch, &projection, &currentExpiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, ErrNotFound
	}
	if err != nil {
		return out, false, err
	}
	var endpointJSON []byte
	if err = tx.QueryRow(ctx, "SELECT endpoint FROM nodes_vpn_installations WHERE node_id=$1", request.NodeID).Scan(&endpointJSON); err != nil {
		return out, false, err
	}
	backend, profile := "", ""
	if len(endpointJSON) > 0 {
		var ep VPNEndpoint
		if json.Unmarshal(endpointJSON, &ep) != nil {
			return out, false, ErrInvalid
		}
		backend = ep.Backend
		profile = ep.ProfileSHA256()
	}
	if backend != request.Backend || profile != request.ProfileSHA256 {
		return out, false, ErrConflict
	}
	if installation != request.InstallationID {
		return out, false, ErrUnauthorized
	}
	if epoch != nil && *epoch != request.EngineEpoch {
		var retired bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM nodes_vpn_policies WHERE node_id=$1 AND engine_epoch=$2)", request.NodeID, request.EngineEpoch).Scan(&retired); err != nil {
			return out, false, err
		}
		if retired {
			return out, false, ErrConflict
		}
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return out, false, err
	}
	now = now.UTC()
	leaseEnd := now.Add(2 * time.Minute)
	grants := []nodewire.VPNGrant{}
	if enabled {
		grants, err = access.New(s.Pool, s.Vault).VPNGrantsTx(ctx, tx, request.NodeID, group, generation+1, leaseEnd, backend)
		if errors.Is(err, access.ErrKey) {
			return out, false, ErrKey
		}
		if errors.Is(err, access.ErrLimit) {
			return out, false, ErrVPNCapacity
		}
		if err != nil {
			return out, false, err
		}
	}
	desiredHash := projectionHash(grants, leaseEnd, group, enabled)
	if backend != "" {
		h := sha256.Sum256([]byte(backend + ":" + profile + ":" + desiredHash))
		desiredHash = hex.EncodeToString(h[:])
	}
	if generation > 0 && epoch != nil && *epoch == request.EngineEpoch && projection != nil && *projection == desiredHash && currentExpiry != nil && currentExpiry.After(now.Add(30*time.Second)) {
		var encrypted []byte
		var storedHash string
		if err = tx.QueryRow(ctx, "SELECT policy_ciphertext,policy_sha256 FROM nodes_vpn_policies WHERE node_id=$1 AND generation=$2", request.NodeID, generation).Scan(&encrypted, &storedHash); err != nil {
			return out, false, err
		}
		plain, e := s.Vault.OpenPolicy(encrypted, vpnAAD(request.NodeID, installation, request.EngineEpoch, generation))
		if e != nil {
			return out, false, ErrKey
		}
		defer clear(plain)
		var signed nodewire.SignedVPNPolicy
		if json.Unmarshal(plain, &signed) != nil {
			return out, false, ErrKey
		}
		pub, _ := nodecontrol.LoadPublicKey(s.Signer.PublicPEM())
		p, e := nodecontrol.VerifyVPN(pub, signed)
		if e != nil || p.Backend != backend || p.ProfileSHA256 != profile || p.NodeID != request.NodeID || p.InstallationID != installation || p.EngineEpoch != request.EngineEpoch || p.Generation != generation || !p.ExpiresAt.Equal(*currentExpiry) || nodecontrol.VPNHash(signed) != storedHash {
			return out, false, ErrKey
		}
		out.Policy = &signed
		return out, true, tx.Commit(ctx)
	}
	policy := nodewire.VPNPolicy{Backend: backend, ProfileSHA256: profile, SchemaVersion: 1, NodeID: request.NodeID, InstallationID: installation, EngineEpoch: request.EngineEpoch, AuthorityEpoch: 1, Generation: generation + 1, IssuedAt: now, ExpiresAt: leaseEnd, Grants: grants}
	signed, err := s.Signer.SignVPN(policy)
	if err != nil {
		return out, false, ErrInvalid
	}
	plain, err := json.Marshal(signed)
	if err != nil {
		return out, false, err
	}
	defer clear(plain)
	encrypted, err := s.Vault.SealPolicy(plain, vpnAAD(request.NodeID, installation, request.EngineEpoch, policy.Generation))
	if err != nil {
		return out, false, ErrKey
	}
	if _, err = tx.Exec(ctx, `INSERT INTO nodes_vpn_policies(node_id,generation,engine_epoch,policy_ciphertext,policy_sha256,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, request.NodeID, policy.Generation, request.EngineEpoch, encrypted, nodecontrol.VPNHash(signed), now, leaseEnd); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE nodes_vpn_installations SET generation=$2,engine_epoch=$3,projection_sha256=$4,policy_expires_at=$5,updated_at=clock_timestamp() WHERE node_id=$1`, request.NodeID, policy.Generation, request.EngineEpoch, desiredHash, leaseEnd); err != nil {
		return out, false, err
	}
	if err = audit.Append(ctx, tx, request.NodeID, "node.vpn_policy_issued", request.NodeID, "succeeded"); err != nil {
		return out, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, false, err
	}
	out.Policy = &signed
	return out, false, nil
}
