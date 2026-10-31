package nodecontrol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodewire"
	"time"
)

const connectionDomain = "salfetka-node-connections-v1\x00"
const MaxConnectionsPlanBytes = 4 * 1024 * 1024

func validConnections(p nodewire.ConnectionsPlan) bool {
	if p.SchemaVersion != 1 || !uuid.MatchString(p.NodeID) || p.Revision < 1 || p.Revision > 9007199254740991 || p.IssuedAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 5*time.Minute || p.Connections == nil || len(p.Connections) > 32 {
		return false
	}
	last := ""
	installations := map[string]bool{}
	listeners := []connection.Listener{}
	for _, c := range p.Connections {
		if !uuid.MatchString(c.ID) || c.ID <= last || !uuid.MatchString(c.InstallationID) || installations[c.InstallationID] || c.Revision < 1 || c.Revision > 9007199254740991 || c.Configuration.Validate() != nil || connection.Hash(c.Configuration) != c.ConfigurationSHA256 {
			return false
		}
		last = c.ID
		installations[c.InstallationID] = true
		s := c.Configuration.Public
		l := connection.Listener{IP: s.ListenIP, Port: s.Port, Network: s.Network()}
		for _, prior := range listeners {
			if connection.Conflicts(prior, l) {
				return false
			}
		}
		listeners = append(listeners, l)
	}
	return true
}
func (s *Signer) SignConnections(p nodewire.ConnectionsPlan) (nodewire.SignedConnectionsPlan, error) {
	if s == nil || !validConnections(p) {
		return nodewire.SignedConnectionsPlan{}, ErrInvalid
	}
	p.IssuedAt = p.IssuedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxConnectionsPlanBytes {
		return nodewire.SignedConnectionsPlan{}, ErrInvalid
	}
	sig := ed25519.Sign(s.key, append([]byte(connectionDomain), raw...))
	return nodewire.SignedConnectionsPlan{Body: string(raw), Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}
func VerifyConnections(pub ed25519.PublicKey, s nodewire.SignedConnectionsPlan) (nodewire.ConnectionsPlan, error) {
	var p nodewire.ConnectionsPlan
	if len(pub) != 32 || len(s.Body) == 0 || len(s.Body) > MaxConnectionsPlanBytes || len(s.Signature) != 86 {
		return p, ErrInvalid
	}
	sig, e := base64.RawURLEncoding.DecodeString(s.Signature)
	if e != nil || base64.RawURLEncoding.EncodeToString(sig) != s.Signature || !ed25519.Verify(pub, append([]byte(connectionDomain), []byte(s.Body)...), sig) {
		return p, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewBufferString(s.Body))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || !validConnections(p) {
		return nodewire.ConnectionsPlan{}, ErrInvalid
	}
	p.IssuedAt = p.IssuedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	canonical, e := json.Marshal(p)
	if e != nil || !bytes.Equal(canonical, []byte(s.Body)) {
		return nodewire.ConnectionsPlan{}, ErrInvalid
	}
	return p, nil
}
