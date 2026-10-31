package nodecontrol

import (
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

func vpnFixture() nodewire.VPNPolicy {
	now := time.Now().UTC()
	return nodewire.VPNPolicy{SchemaVersion: 1, NodeID: "11111111-1111-4111-8111-111111111111", InstallationID: "22222222-2222-4222-8222-222222222222", EngineEpoch: "0123456789abcdef0123456789abcdef", AuthorityEpoch: 1, Generation: 3, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Grants: []nodewire.VPNGrant{{ID: "33333333-3333-4333-8333-333333333333", Generation: 3, Enabled: true, Credential: "44444444-4444-4444-8444-444444444444", ExpiresAt: now.Add(time.Minute)}}}
}
func TestVPNPolicySignatureCanonicalAndDomain(t *testing.T) {
	s := testSigner(t)
	pub, _ := LoadPublicKey(s.PublicPEM())
	p := vpnFixture()
	signed, err := s.SignVPN(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyVPN(pub, signed)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("roundtrip", err)
	}
	for _, raw := range []string{signed.Body + " ", strings.Replace(signed.Body, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), strings.Replace(signed.Body, `"grants":`, `"unknown":null,"grants":`, 1), strings.Replace(signed.Body, `"generation":3`, `"generation":3.0`, 1)} {
		sig := ed25519.Sign(s.key, append([]byte(vpnDomain), []byte(raw)...))
		if _, err := VerifyVPN(pub, nodewire.SignedVPNPolicy{Body: raw, Signature: base64.RawURLEncoding.EncodeToString(sig)}); err == nil {
			t.Fatal("noncanonical policy")
		}
	}
	wrong := signed
	wrong.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, append([]byte(domain), []byte(signed.Body)...)))
	if _, err := VerifyVPN(pub, wrong); err == nil {
		t.Fatal("cross-domain accepted")
	}
	other, _ := LoadPublicKey(testSigner(t).PublicPEM())
	if _, err := VerifyVPN(other, signed); err == nil {
		t.Fatal("foreign signer")
	}
}
func TestVPNPolicyRejectsUnboundedAmbiguousGrants(t *testing.T) {
	s := testSigner(t)
	cases := map[string]func(*nodewire.VPNPolicy){"long lease": func(p *nodewire.VPNPolicy) { p.ExpiresAt = p.IssuedAt.Add(MaxVPNLease + time.Second) }, "grant beyond lease": func(p *nodewire.VPNPolicy) { p.Grants[0].ExpiresAt = p.ExpiresAt.Add(time.Second) }, "empty ambiguity": func(p *nodewire.VPNPolicy) { p.Grants = nil }, "duplicate": func(p *nodewire.VPNPolicy) { p.Grants = append(p.Grants, p.Grants[0]) }, "generation mismatch": func(p *nodewire.VPNPolicy) { p.Grants[0].Generation-- }, "disabled secret": func(p *nodewire.VPNPolicy) { p.Grants[0].Enabled = false }, "alias credential": func(p *nodewire.VPNPolicy) {
		g := p.Grants[0]
		g.ID = "55555555-5555-4555-8555-555555555555"
		g.Credential = "44444444-4444-4999-8444-444444444444"
		p.Grants = append(p.Grants, g)
	}, "future epoch": func(p *nodewire.VPNPolicy) { p.AuthorityEpoch++ }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := vpnFixture()
			mutate(&p)
			if _, err := s.SignVPN(p); err == nil {
				t.Fatal("invalid policy signed")
			}
		})
	}
	p := vpnFixture()
	p.Grants = []nodewire.VPNGrant{}
	if _, err := s.SignVPN(p); err != nil {
		t.Fatal("explicit deny-all policy rejected")
	}
}

func TestPersonalPolicyRejectsAmbiguousBindings(t *testing.T) {
	s := testSigner(t)
	p := vpnFixture()
	p.Backend = "olcrtc"
	p.ProfileSHA256 = strings.Repeat("f", 64)
	p.Grants[0].Credential = strings.Repeat("a", 64)
	p.Grants[0].AccountID = "11111111-1111-4111-8111-111111111111"
	p.Grants[0].RoomID = strings.Repeat("b", 64)
	second := p.Grants[0]
	second.ID = "44444444-4444-4444-8444-444444444444"
	second.Credential = strings.Repeat("c", 64)
	p.Grants = append(p.Grants, second)
	if _, e := s.SignVPN(p); e != nil {
		t.Fatal("same account devices rejected", e)
	}
	for _, kind := range []string{"collision", "split", "missing", "mixed"} {
		q := p
		q.Grants = append([]nodewire.VPNGrant(nil), p.Grants...)
		switch kind {
		case "collision":
			q.Grants[1].AccountID = "22222222-2222-4222-8222-222222222222"
		case "split":
			q.Grants[1].RoomID = strings.Repeat("d", 64)
		case "missing":
			q.Grants[1].RoomID = ""
		case "mixed":
			q.Grants[1].RoomID = ""
			q.Grants[1].AccountID = ""
		}
		if _, e := s.SignVPN(q); e == nil {
			t.Fatalf("accepted %s", kind)
		}
	}
}
