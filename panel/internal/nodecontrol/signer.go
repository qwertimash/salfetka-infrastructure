// Package nodecontrol signs bounded canonical agent settings. It has no database
// dependency and can be used by the agent to verify an explicitly pinned signer.
package nodecontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"time"

	"salfetka/panel/internal/nodewire"
)

var ErrInvalid = errors.New("node_command_invalid")

const domain = "salfetka-node-command-v1\x00"

type Signer struct{ key ed25519.PrivateKey }

func GenerateSigner() ([]byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrInvalid
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrInvalid
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func block(raw []byte, kind string) (*pem.Block, error) {
	raw = bytes.TrimSpace(raw)
	start := []byte("-----BEGIN " + kind + "-----")
	end := []byte("-----END " + kind + "-----")
	if len(raw) > 4096 || !bytes.HasPrefix(raw, start) || !bytes.HasSuffix(raw, end) || bytes.Count(raw, []byte("-----BEGIN ")) != 1 {
		return nil, ErrInvalid
	}
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != kind || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalid
	}
	return b, nil
}
func LoadSigner(raw []byte) (*Signer, error) {
	b, err := block(raw, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, ErrInvalid
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalid
	}
	return &Signer{ed}, nil
}
func (s *Signer) PublicPEM() []byte {
	if s == nil {
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(s.key.Public())
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
func LoadPublicKey(raw []byte) (ed25519.PublicKey, error) {
	b, err := block(raw, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalid
	}
	return key, nil
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func PayloadHash(config nodewire.AgentConfig) string {
	raw, _ := json.Marshal(config)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func CommandHash(s nodewire.SignedCommand) string {
	sum := sha256.Sum256([]byte(s.Body))
	return hex.EncodeToString(sum[:])
}
func valid(c nodewire.Command) bool {
	return c.SchemaVersion == 1 && uuid.MatchString(c.NodeID) && uuid.MatchString(c.OperationID) && c.AuthorityEpoch == 1 && c.Generation >= 1 && c.Generation <= 9007199254740991 && c.Kind == "agent.config.set" && c.Payload.HeartbeatIntervalSeconds >= 5 && c.Payload.HeartbeatIntervalSeconds <= 30 && c.PayloadSHA256 == PayloadHash(c.Payload) && !c.CreatedAt.IsZero() && c.DeadlineAt.After(c.CreatedAt) && c.DeadlineAt.Sub(c.CreatedAt) <= 10*time.Minute
}
func (s *Signer) Sign(c nodewire.Command) (nodewire.SignedCommand, error) {
	if s == nil || !valid(c) {
		return nodewire.SignedCommand{}, ErrInvalid
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.DeadlineAt = c.DeadlineAt.UTC()
	raw, err := json.Marshal(c)
	if err != nil {
		return nodewire.SignedCommand{}, ErrInvalid
	}
	sig := ed25519.Sign(s.key, append([]byte(domain), raw...))
	return nodewire.SignedCommand{Body: string(raw), Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}
func Verify(pub ed25519.PublicKey, s nodewire.SignedCommand) (nodewire.Command, error) {
	var c nodewire.Command
	if len(pub) != ed25519.PublicKeySize || len(s.Body) == 0 || len(s.Body) > 4096 || len(s.Signature) != 86 {
		return c, ErrInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) != 64 || base64.RawURLEncoding.EncodeToString(sig) != s.Signature || !ed25519.Verify(pub, append([]byte(domain), []byte(s.Body)...), sig) {
		return c, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader([]byte(s.Body)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(&struct{}{}) != io.EOF || !valid(c) {
		return nodewire.Command{}, ErrInvalid
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.DeadlineAt = c.DeadlineAt.UTC()
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, []byte(s.Body)) {
		return nodewire.Command{}, ErrInvalid
	}
	return c, nil
}
