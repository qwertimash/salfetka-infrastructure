package nodes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/secrets"
)

var (
	ErrInvalid      = errors.New("node_invalid")
	ErrNotFound     = errors.New("node_not_found")
	ErrConflict     = errors.New("node_conflict")
	ErrRevision     = errors.New("node_revision")
	ErrProof        = errors.New("node_proof_invalid")
	ErrEnrollment   = errors.New("node_enrollment_invalid")
	ErrExpired      = errors.New("node_enrollment_expired")
	ErrUnauthorized = errors.New("node_unauthorized")
	ErrKey          = errors.New("node_key_unavailable")
)

type Node struct {
	OwnerNodeID          *string                    `json:"owner_node_id,omitempty"`
	ID                   string                     `json:"id"`
	Name                 string                     `json:"name"`
	State                string                     `json:"state"`
	Revision             int64                      `json:"revision"`
	Serial               *string                    `json:"serial"`
	CertificateExpiresAt *time.Time                 `json:"certificate_expires_at"`
	LastSeenAt           *time.Time                 `json:"last_seen_at"`
	Inventory            *nodewire.HeartbeatRequest `json:"inventory"`
	ContactState         string                     `json:"contact_state"`
	EngineState          string                     `json:"engine_state"`
	CreatedAt            time.Time                  `json:"created_at"`
	UpdatedAt            time.Time                  `json:"updated_at"`
}
type EnrollmentSecret struct {
	NodeID    string    `json:"node_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
type EnrollmentCreated struct {
	Node       Node             `json:"node"`
	Enrollment EnrollmentSecret `json:"enrollment"`
}
type Mutation struct {
	ActorID, Route, TargetID, Key string
	Revision                      int64
	Payload                       any
}
type Store struct {
	Pool      *pgxpool.Pool
	Vault     *secrets.Vault
	Authority *Authority
	Signer    *nodecontrol.Signer
}

func New(pool *pgxpool.Pool, vault *secrets.Vault, authority *Authority) *Store {
	return &Store{Pool: pool, Vault: vault, Authority: authority}
}

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

func (s *Store) mutate(ctx context.Context, tx pgx.Tx, m Mutation, out any, fn func() error) (bool, error) {
	if !database.ValidID(m.ActorID) || !idempotencyPattern.MatchString(m.Key) || m.Route == "" || len(m.Route) > 100 || (m.TargetID != "" && !database.ValidID(m.TargetID)) {
		return false, ErrInvalid
	}
	if s.Vault == nil {
		return false, ErrKey
	}
	raw, err := json.Marshal(struct {
		Revision int64
		Payload  any
	}{m.Revision, m.Payload})
	if err != nil {
		return false, ErrInvalid
	}
	hash := sha256.Sum256(raw)
	scope := m.ActorID + "/" + m.Route + "/" + m.TargetID + "/" + m.Key
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,3))", scope); err != nil {
		return false, err
	}
	var existingHash, encrypted []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,result_ciphertext FROM nodes_admin_mutations WHERE actor_id=$1 AND route=$2 AND target_id=$3 AND idempotency_key=$4`, m.ActorID, m.Route, m.TargetID, m.Key).Scan(&existingHash, &encrypted)
	if err == nil {
		if subtle.ConstantTimeCompare(hash[:], existingHash) != 1 {
			return false, ErrConflict
		}
		plain, e := s.Vault.Open(encrypted, "node-admin-result:"+scope)
		if e != nil {
			return false, ErrKey
		}
		defer clear(plain)
		return true, json.Unmarshal(plain, out)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if m.TargetID != "" {
		var owner *string
		err = tx.QueryRow(ctx, "SELECT owner_node_id::text FROM nodes_registry WHERE id=$1", m.TargetID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if owner != nil {
			if _, err = tx.Exec(ctx, "SELECT id FROM nodes_registry WHERE id=$1 FOR UPDATE", *owner); err != nil {
				return false, err
			}
		}
		var rev int64
		err = tx.QueryRow(ctx, "SELECT revision FROM nodes_registry WHERE id=$1 FOR UPDATE", m.TargetID).Scan(&rev)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if rev != m.Revision {
			return false, ErrRevision
		}
	}
	if err = fn(); err != nil {
		return false, err
	}
	raw, err = json.Marshal(out)
	if err != nil {
		return false, err
	}
	defer clear(raw)
	encrypted, err = s.Vault.Seal(raw, "node-admin-result:"+scope)
	if err != nil {
		return false, ErrKey
	}
	_, err = tx.Exec(ctx, `INSERT INTO nodes_admin_mutations(actor_id,route,target_id,idempotency_key,request_hash,result_ciphertext) VALUES($1,$2,$3,$4,$5,$6)`, m.ActorID, m.Route, m.TargetID, m.Key, hash[:], encrypted)
	return false, err
}
func validName(name string) bool {
	if !utf8.ValidString(name) || name != strings.TrimSpace(name) || utf8.RuneCountInString(name) < 2 || utf8.RuneCountInString(name) > 80 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

const nodeColumns = "id::text,name,state,revision,serial,certificate_expires_at,last_seen_at,inventory,created_at,updated_at,clock_timestamp(),owner_node_id::text"

func scanNode(row pgx.Row) (Node, error) {
	var n Node
	var raw []byte
	var now time.Time
	err := row.Scan(&n.ID, &n.Name, &n.State, &n.Revision, &n.Serial, &n.CertificateExpiresAt, &n.LastSeenAt, &raw, &n.CreatedAt, &n.UpdatedAt, &now, &n.OwnerNodeID)
	if err != nil {
		return n, err
	}
	if raw != nil {
		if err = json.Unmarshal(raw, &n.Inventory); err != nil {
			return n, err
		}
	}
	n.EngineState = "not_configured"
	n.ContactState = "unknown"
	if n.LastSeenAt != nil {
		n.ContactState = "stale"
		if n.State == "active" && n.CertificateExpiresAt != nil && n.CertificateExpiresAt.After(now) && now.Sub(*n.LastSeenAt) < 60*time.Second && now.After(n.LastSeenAt.Add(-time.Second)) {
			n.ContactState = "fresh"
		}
	}
	return n, nil
}
func (s *Store) GetTx(ctx context.Context, tx pgx.Tx, id string) (Node, error) {
	if !database.ValidID(id) {
		return Node{}, ErrInvalid
	}
	n, err := scanNode(tx.QueryRow(ctx, "SELECT "+nodeColumns+" FROM nodes_registry WHERE id=$1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return n, err
}
func (s *Store) ListTx(ctx context.Context, tx pgx.Tx, limit int, cursor string) ([]Node, error) {
	if limit < 1 || limit > 100 || (cursor != "" && !database.ValidID(cursor)) {
		return nil, ErrInvalid
	}
	var at time.Time
	if cursor != "" {
		if err := tx.QueryRow(ctx, "SELECT created_at FROM nodes_registry WHERE id=$1", cursor).Scan(&at); errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		} else if err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(ctx, "SELECT "+nodeColumns+" FROM nodes_registry WHERE NOT EXISTS (SELECT 1 FROM server_nodes sn WHERE sn.node_id=nodes_registry.id) AND ($1='' OR (created_at,id)<($2,NULLIF($1,'')::uuid)) ORDER BY created_at DESC,id DESC LIMIT $3", cursor, at, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		n, e := scanNode(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) CreateTx(ctx context.Context, tx pgx.Tx, m Mutation, name string) (Node, bool, error) {
	m.Payload = name
	var out Node
	replay, err := s.mutate(ctx, tx, m, &out, func() error {
		if !validName(name) || m.TargetID != "" || m.Revision != 0 {
			return ErrInvalid
		}
		id, err := database.NewID()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO nodes_registry(id,name) VALUES($1,$2)", id, name); err != nil {
			return err
		}
		if err = audit.Append(ctx, tx, m.ActorID, "node.created", id, "accepted"); err != nil {
			return err
		}
		out, err = s.GetTx(ctx, tx, id)
		return err
	})
	return out, replay, err
}
func (s *Store) EnrollmentTx(ctx context.Context, tx pgx.Tx, m Mutation) (EnrollmentCreated, bool, error) {
	m.Payload = struct{}{}
	var out EnrollmentCreated
	replay, err := s.mutate(ctx, tx, m, &out, func() error {
		if s.Authority == nil {
			return ErrAuthority
		}
		n, err := s.GetTx(ctx, tx, m.TargetID)
		if err != nil {
			return err
		}
		if n.State != "pending" || n.OwnerNodeID != nil {
			return ErrConflict
		}
		secret := make([]byte, 32)
		if _, err = rand.Read(secret); err != nil {
			return err
		}
		defer clear(secret)
		token := base64.RawURLEncoding.EncodeToString(secret)
		hash := sha256.Sum256([]byte(token))
		id, err := database.NewID()
		if err != nil {
			return err
		}
		var expires time.Time
		if err = tx.QueryRow(ctx, "SELECT date_trunc('second',clock_timestamp())+interval '10 minutes'").Scan(&expires); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE nodes_enrollments SET revoked=true WHERE node_id=$1 AND NOT revoked", m.TargetID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO nodes_enrollments(id,node_id,token_hash,expires_at) VALUES($1,$2,$3,$4)", id, m.TargetID, hash[:], expires); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE nodes_registry SET revision=revision+1,updated_at=clock_timestamp() WHERE id=$1", m.TargetID); err != nil {
			return err
		}
		if err = audit.Append(ctx, tx, m.ActorID, "node.enrollment_created", m.TargetID, "accepted"); err != nil {
			return err
		}
		out.Node, err = s.GetTx(ctx, tx, m.TargetID)
		out.Enrollment = EnrollmentSecret{m.TargetID, token, expires}
		return err
	})
	return out, replay, err
}
func (s *Store) RevokeTx(ctx context.Context, tx pgx.Tx, m Mutation) (Node, bool, error) {
	m.Payload = struct{}{}
	var out Node
	replay, err := s.mutate(ctx, tx, m, &out, func() error {
		n, err := s.GetTx(ctx, tx, m.TargetID)
		if err != nil {
			return err
		}
		if n.State == "revoked" {
			return ErrConflict
		}
		if _, err = tx.Exec(ctx, "UPDATE nodes_registry SET state='revoked',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 OR owner_node_id=$1", m.TargetID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE nodes_enrollments SET revoked=true WHERE node_id=$1", m.TargetID); err != nil {
			return err
		}
		if n.OwnerNodeID != nil {
			if _, err = tx.Exec(ctx, "UPDATE server_nodes SET revision=revision+1 WHERE node_id=$1", *n.OwnerNodeID); err != nil {
				return err
			}
		}
		if err = audit.Append(ctx, tx, m.ActorID, "node.revoked", m.TargetID, "accepted"); err != nil {
			return err
		}
		out, err = s.GetTx(ctx, tx, m.TargetID)
		return err
	})
	return out, replay, err
}
func (s *Store) Enroll(ctx context.Context, r nodewire.EnrollmentRequest) (nodewire.EnrollmentResponse, bool, error) {
	var out nodewire.EnrollmentResponse
	if r.SchemaVersion != 1 || !database.ValidID(r.NodeID) || !database.ValidID(r.RequestID) || len(r.Token) != 43 {
		return out, false, ErrInvalid
	}
	tokenBytes, err := base64.RawURLEncoding.DecodeString(r.Token)
	if err != nil || len(tokenBytes) != 32 || base64.RawURLEncoding.EncodeToString(tokenBytes) != r.Token {
		return out, false, ErrInvalid
	}
	csr, err := parseCSR(r.CSRPEM)
	if err != nil {
		return out, false, err
	}
	csrHash := sha256.Sum256(csr.Raw)
	tokenHash := sha256.Sum256([]byte(r.Token))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer database.Rollback(tx)
	var state string
	if err = tx.QueryRow(ctx, "SELECT state FROM nodes_registry WHERE id=$1 FOR UPDATE", r.NodeID).Scan(&state); errors.Is(err, pgx.ErrNoRows) {
		return out, false, ErrEnrollment
	} else if err != nil {
		return out, false, err
	}
	if state == "revoked" {
		return out, false, ErrEnrollment
	}
	var id string
	var expires, now time.Time
	var used *time.Time
	var requestID *string
	var storedHash, storedResponse []byte
	var revoked bool
	err = tx.QueryRow(ctx, "SELECT id::text,expires_at,used_at,request_id::text,csr_hash,certificate_response,revoked,clock_timestamp() FROM nodes_enrollments WHERE node_id=$1 AND token_hash=$2 FOR UPDATE", r.NodeID, tokenHash[:]).Scan(&id, &expires, &used, &requestID, &storedHash, &storedResponse, &revoked, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, ErrEnrollment
	}
	if err != nil {
		return out, false, err
	}
	if revoked {
		return out, false, ErrEnrollment
	}
	if used != nil {
		if requestID == nil || *requestID != r.RequestID || subtle.ConstantTimeCompare(csrHash[:], storedHash) != 1 {
			return out, false, ErrConflict
		}
		if err = json.Unmarshal(storedResponse, &out); err != nil {
			return out, false, err
		}
		if state != "active" || !out.ExpiresAt.After(now) {
			return out, false, ErrExpired
		}
		if err = tx.Commit(ctx); err != nil {
			return out, false, err
		}
		return out, true, nil
	}
	if !expires.After(now) {
		return out, false, ErrExpired
	}
	if state != "pending" {
		return out, false, ErrConflict
	}
	out, err = s.Authority.issue(r.NodeID, csr, now)
	if err != nil {
		return out, false, err
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE nodes_enrollments SET used_at=clock_timestamp(),request_id=$2,csr_hash=$3,certificate_response=$4 WHERE id=$1", id, r.RequestID, csrHash[:], encoded); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE nodes_registry SET state='active',serial=$2,public_key=$3,certificate_expires_at=$4,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1", r.NodeID, out.Serial, []byte(csr.PublicKey.(ed25519.PublicKey)), out.ExpiresAt); err != nil {
		return out, false, err
	}
	if err = audit.Append(ctx, tx, r.NodeID, "node.enrolled", r.NodeID, "succeeded"); err != nil {
		return out, false, err
	}
	err = tx.Commit(ctx)
	return out, false, err
}
func (s *Store) authorizeLeaf(cert *x509.Certificate, nodeID string) error {
	if s.Authority == nil || cert == nil || !database.ValidID(nodeID) || len(cert.URIs) != 1 || cert.URIs[0].String() != nodewire.IdentityURIPrefix+nodeID || cert.Subject.CommonName != nodeID {
		return ErrUnauthorized
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return ErrUnauthorized
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: s.Authority.CertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrUnauthorized
	}
	return nil
}

var agentVersionPattern = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,64}$`)

func validateHeartbeat(r nodewire.HeartbeatRequest) bool {
	if !validSite(r.Site, time.Time{}) {
		return false
	}
	if r.SchemaVersion != 1 || !database.ValidID(r.NodeID) || !database.ValidID(r.BootID) || r.Sequence < 1 || r.Sequence > 9007199254740991 || !agentVersionPattern.MatchString(r.Version) || len(r.Capabilities) > 4 || r.Capabilities == nil {
		return false
	}
	switch r.Platform {
	case "linux", "darwin", "windows", "freebsd":
	default:
		return false
	}
	switch r.Arch {
	case "amd64", "arm64", "arm", "386":
	default:
		return false
	}
	seen := map[string]bool{}
	for _, cap := range r.Capabilities {
		if seen[cap] || (cap != "enrollment" && cap != "heartbeat" && cap != "certificate_renewal" && cap != "managed_connections_v1") {
			return false
		}
		seen[cap] = true
	}
	return true
}
func (s *Store) Heartbeat(ctx context.Context, cert *x509.Certificate, r nodewire.HeartbeatRequest) (nodewire.HeartbeatResponse, bool, error) {
	var out nodewire.HeartbeatResponse
	if !validateHeartbeat(r) {
		return out, false, ErrInvalid
	}
	if err := s.authorizeLeaf(cert, r.NodeID); err != nil {
		return out, false, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return out, false, ErrInvalid
	}
	hash := sha256.Sum256(raw)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer database.Rollback(tx)
	if err = s.lockAuthorizedNode(ctx, tx, cert, r.NodeID); err != nil {
		return out, false, err
	}
	if err = s.validateSiteOwner(ctx, tx, r.NodeID, r.Site); err != nil {
		return out, false, err
	}
	var currentBoot *string
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT current_boot_id::text,clock_timestamp() FROM nodes_registry WHERE id=$1", r.NodeID).Scan(&currentBoot, &now); err != nil {
		return out, false, err
	}
	var previousSequence int64
	var previousHash, response []byte
	err = tx.QueryRow(ctx, "SELECT sequence,request_hash,response FROM nodes_heartbeat_boots WHERE node_id=$1 AND boot_id=$2", r.NodeID, r.BootID).Scan(&previousSequence, &previousHash, &response)
	if err == nil {
		if currentBoot == nil || *currentBoot != r.BootID || r.Sequence < previousSequence {
			return out, false, ErrConflict
		}
		if r.Sequence == previousSequence {
			if subtle.ConstantTimeCompare(previousHash, hash[:]) != 1 {
				return out, false, ErrConflict
			}
			if err = json.Unmarshal(response, &out); err != nil {
				return out, false, err
			}
			if err = tx.Commit(ctx); err != nil {
				return out, false, err
			}
			return out, true, nil
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return out, false, err
	}
	out = nodewire.HeartbeatResponse{SchemaVersion: 1, NodeID: r.NodeID, Sequence: r.Sequence, ReceivedAt: now, Status: "recorded", EngineState: "not_configured"}
	response, err = json.Marshal(out)
	if err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO nodes_heartbeat_boots(node_id,boot_id,sequence,request_hash,response) VALUES($1,$2,$3,$4,$5) ON CONFLICT(node_id,boot_id) DO UPDATE SET sequence=excluded.sequence,request_hash=excluded.request_hash,response=excluded.response", r.NodeID, r.BootID, r.Sequence, hash[:], response); err != nil {
		return out, false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE nodes_registry SET current_boot_id=$2,last_seen_at=$3,inventory=$4 WHERE id=$1", r.NodeID, r.BootID, now, raw); err != nil {
		return out, false, err
	}
	err = tx.Commit(ctx)
	return out, false, err
}
