// Package nodeagent implements durable node identity, certificate renewal,
// heartbeat and signed agent settings. VPN engine grants are a separate stage.
package nodeagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"
	"time"

	"salfetka/panel/internal/nodewire"
)

type enrollmentToken struct {
	NodeID    string    `json:"node_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type controlWatermark struct {
	AuthorityEpoch    int64                   `json:"authority_epoch"`
	Generation        int64                   `json:"generation"`
	PayloadHash       string                  `json:"payload_hash"`
	SignerHash        string                  `json:"signer_sha256"`
	Phase             string                  `json:"phase"`
	Envelope          *nodewire.SignedCommand `json:"envelope,omitempty"`
	AppliedGeneration int64                   `json:"applied_generation"`
	AppliedEnvelope   *nodewire.SignedCommand `json:"applied_envelope,omitempty"`
	ActiveConfig      *nodewire.AgentConfig   `json:"active_config,omitempty"`
	Receipt           *nodewire.Receipt       `json:"receipt,omitempty"`
	ReceiptPending    bool                    `json:"receipt_pending"`
	WallHighWater     time.Time               `json:"wall_high_water"`
}
type localState struct {
	SchemaVersion int                          `json:"schema_version"`
	NodeID        string                       `json:"node_id"`
	PanelURL      string                       `json:"panel_url"`
	ServerCAHash  string                       `json:"server_ca_sha256"`
	RequestID     string                       `json:"request_id"`
	TokenHash     string                       `json:"token_sha256"`
	PrivateKeyPEM string                       `json:"private_key_pem"`
	CSRPEM        string                       `json:"csr_pem"`
	Enrollment    *nodewire.EnrollmentResponse `json:"enrollment,omitempty"`
	LastHeartbeat *nodewire.HeartbeatResponse  `json:"last_heartbeat,omitempty"`
	Control       *controlWatermark            `json:"control,omitempty"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fault("node_random_failed")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func digest(value []byte) string { hash := sha256.Sum256(value); return hex.EncodeToString(hash[:]) }

// Decode the first block without allowing pem.Decode to skip malformed input.
// Private material and returned identities must contain exactly one block.
func firstPEM(raw []byte, kind string) (*pem.Block, []byte, error) {
	raw = bytes.TrimSpace(raw)
	begin, end := []byte("-----BEGIN "+kind+"-----"), []byte("-----END "+kind+"-----")
	if !bytes.HasPrefix(raw, begin) {
		return nil, nil, fault("node_pem_invalid")
	}
	i := bytes.Index(raw, end)
	if i < 0 {
		return nil, nil, fault("node_pem_invalid")
	}
	stop := i + len(end)
	if bytes.Contains(raw[len(begin):stop], []byte("-----BEGIN ")) {
		return nil, nil, fault("node_pem_invalid")
	}
	block, rest := pem.Decode(raw[:stop])
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fault("node_pem_invalid")
	}
	return block, bytes.TrimSpace(raw[stop:]), nil
}
func onlyPEM(raw, kind string) (*pem.Block, error) {
	block, rest, err := firstPEM([]byte(raw), kind)
	if err != nil || len(rest) != 0 {
		return nil, fault("node_pem_invalid")
	}
	return block, nil
}
func serverRoots(raw []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		block, rest, err := firstPEM(raw, "CERTIFICATE")
		if err != nil {
			return nil, fault("node_server_ca_invalid")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fault("node_server_ca_invalid")
		}
		pool.AddCert(cert)
		count++
		raw = rest
	}
	if count == 0 {
		return nil, fault("node_server_ca_invalid")
	}
	return pool, nil
}
func decodeJSON(raw []byte, target any) error {
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	if uniqueJSON(check, 0) != nil {
		return fault("node_state_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return fault("node_state_invalid")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fault("node_state_invalid")
	}
	return nil
}
func uniqueJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return fault("node_state_invalid")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fault("node_state_invalid")
			}
			seen[name] = true
			if err := uniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fault("node_state_invalid")
	}
	_, err = decoder.Token()
	return err
}
func parseKey(raw string) (ed25519.PrivateKey, error) {
	block, err := onlyPEM(raw, "PRIVATE KEY")
	if err != nil {
		return nil, fault("node_key_invalid")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fault("node_key_invalid")
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fault("node_key_invalid")
	}
	return ed, nil
}
func parseCSR(raw string) (*x509.CertificateRequest, error) {
	block, err := onlyPEM(raw, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, fault("node_csr_invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, fault("node_csr_invalid")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, fault("node_csr_invalid")
	}
	return csr, nil
}
func newState(cfg Config, ca []byte, token enrollmentToken) (localState, error) {
	var s localState
	tokenBytes, tokenErr := base64.RawURLEncoding.Strict().DecodeString(token.Token)
	if !uuidPattern.MatchString(token.NodeID) || tokenErr != nil || len(tokenBytes) != 32 || base64.RawURLEncoding.EncodeToString(tokenBytes) != token.Token {
		return s, fault("node_enrollment_file_invalid")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return s, fault("node_random_failed")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return s, fault("node_key_generation_failed")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: token.NodeID}}, key)
	if err != nil {
		return s, fault("node_csr_generation_failed")
	}
	id, err := newID()
	if err != nil {
		return s, err
	}
	return localState{SchemaVersion: 1, NodeID: token.NodeID, PanelURL: cfg.PanelURL, ServerCAHash: digest(ca), RequestID: id, TokenHash: digest([]byte(token.Token)), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}, nil
}
func validateState(s localState, cfg Config, ca []byte) (ed25519.PrivateKey, error) {
	if (s.SchemaVersion != 1 && s.SchemaVersion != 2) || !uuidPattern.MatchString(s.NodeID) || !uuidPattern.MatchString(s.RequestID) || len(s.TokenHash) != 64 {
		return nil, fault("node_state_invalid")
	}
	if s.SchemaVersion == 1 && s.Control != nil {
		return nil, fault("node_state_requires_newer_runtime")
	}
	if s.SchemaVersion == 2 && s.Control == nil {
		return nil, fault("node_state_invalid")
	}
	if s.PanelURL != cfg.PanelURL || s.ServerCAHash != digest(ca) {
		return nil, fault("node_identity_configuration_changed")
	}
	key, err := parseKey(s.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	csr, err := parseCSR(s.CSRPEM)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(csr.PublicKey.(ed25519.PublicKey), key.Public().(ed25519.PublicKey)) {
		return nil, fault("node_identity_key_mismatch")
	}
	if s.Enrollment != nil {
		if _, err = verifyEnrollment(*s.Enrollment, s.NodeID, key); err != nil {
			return nil, err
		}
	}
	return key, nil
}
