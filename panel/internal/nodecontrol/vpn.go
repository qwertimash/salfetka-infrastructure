package nodecontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"salfetka/panel/internal/nodewire"
)

const vpnDomain = "salfetka-vpn-policy-v1\x00"
const MaxVPNLease = 5 * time.Minute
const MaxVPNGrants = 128

func validVPN(p nodewire.VPNPolicy) bool {
	if !nodewire.ValidBackend(p.Backend) || p.SchemaVersion != 1 || len(p.EngineEpoch) != 32 || !validEngineEpoch(p.EngineEpoch) || !uuid.MatchString(p.NodeID) || !uuid.MatchString(p.InstallationID) || p.AuthorityEpoch != 1 || p.Generation < 1 || p.Generation > 9007199254740991 || p.IssuedAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > MaxVPNLease || p.Grants == nil || len(p.Grants) > MaxVPNGrants {
		return false
	}
	if p.Backend == nodewire.BackendOLCRTC {
		if !nodewire.ValidOLCKey(p.ProfileSHA256) {
			return false
		}
	} else if p.ProfileSHA256 != "" && !nodewire.ValidOLCKey(p.ProfileSHA256) {
		return false
	}
	prior := ""
	keys := map[string]bool{}
	accounts := map[string]string{}
	rooms := map[string]string{}
	mode := -1
	for _, g := range p.Grants {
		if !uuid.MatchString(g.ID) || g.ID <= prior || g.Generation != p.Generation {
			return false
		}
		prior = g.ID
		if g.AccountID != "" || g.RoomID != "" {
			if p.Backend != nodewire.BackendOLCRTC || !uuid.MatchString(g.AccountID) || !nodewire.ValidOLCKey(g.RoomID) || !g.Enabled {
				return false
			}
			if mode == 0 {
				return false
			}
			mode = 1
			if room, ok := accounts[g.AccountID]; ok && room != g.RoomID {
				return false
			}
			if account, ok := rooms[g.RoomID]; ok && account != g.AccountID {
				return false
			}
			accounts[g.AccountID] = g.RoomID
			rooms[g.RoomID] = g.AccountID
			if len(accounts) > 100 {
				return false
			}
		} else if g.Enabled {
			if mode == 1 {
				return false
			}
			mode = 0
		}
		if g.Enabled {
			validKey := uuid.MatchString(g.Credential)
			if p.Backend == nodewire.BackendOLCRTC {
				validKey = nodewire.ValidOLCKey(g.Credential)
			}
			if !validKey || !g.ExpiresAt.After(p.IssuedAt) || g.ExpiresAt.After(p.ExpiresAt) {
				return false
			}
			// Xray normalizes the UUID version/variant bytes; detect aliases too.
			key := g.Credential
			if p.Backend != nodewire.BackendOLCRTC {
				key = g.Credential[:14] + "0000" + g.Credential[18:]
			}
			if keys[key] {
				return false
			}
			keys[key] = true
		} else if g.Credential != "" || !g.ExpiresAt.IsZero() {
			return false
		}
	}
	return true
}
func canonicalVPN(p nodewire.VPNPolicy) nodewire.VPNPolicy {
	p.IssuedAt = p.IssuedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	grants := make([]nodewire.VPNGrant, len(p.Grants))
	copy(grants, p.Grants)
	for i := range grants {
		grants[i].ExpiresAt = grants[i].ExpiresAt.UTC()
	}
	p.Grants = grants
	return p
}
func (s *Signer) SignVPN(p nodewire.VPNPolicy) (nodewire.SignedVPNPolicy, error) {
	if s == nil || !validVPN(p) {
		return nodewire.SignedVPNPolicy{}, ErrInvalid
	}
	p = canonicalVPN(p)
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 64*1024 {
		return nodewire.SignedVPNPolicy{}, ErrInvalid
	}
	sig := ed25519.Sign(s.key, append([]byte(vpnDomain), raw...))
	return nodewire.SignedVPNPolicy{Body: string(raw), Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}
func VerifyVPN(pub ed25519.PublicKey, s nodewire.SignedVPNPolicy) (nodewire.VPNPolicy, error) {
	var p nodewire.VPNPolicy
	if len(pub) != 32 || len(s.Body) == 0 || len(s.Body) > 64*1024 || len(s.Signature) != 86 {
		return p, ErrInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) != 64 || base64.RawURLEncoding.EncodeToString(sig) != s.Signature || !ed25519.Verify(pub, append([]byte(vpnDomain), []byte(s.Body)...), sig) {
		return p, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader([]byte(s.Body)))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF || !validVPN(p) {
		return nodewire.VPNPolicy{}, ErrInvalid
	}
	p = canonicalVPN(p)
	raw, err := json.Marshal(p)
	if err != nil || !bytes.Equal(raw, []byte(s.Body)) {
		return nodewire.VPNPolicy{}, ErrInvalid
	}
	return p, nil
}
func VPNHash(s nodewire.SignedVPNPolicy) string {
	sum := sha256.Sum256([]byte(s.Body))
	return hex.EncodeToString(sum[:])
}

func validEngineEpoch(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == s
}
