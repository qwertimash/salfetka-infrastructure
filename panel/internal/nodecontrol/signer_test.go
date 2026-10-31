package nodecontrol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"salfetka/panel/internal/nodewire"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	raw, e := GenerateSigner()
	if e != nil {
		t.Fatal(e)
	}
	s, e := LoadSigner(raw)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func testCommand() nodewire.Command {
	p := nodewire.AgentConfig{HeartbeatIntervalSeconds: 5}
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	return nodewire.Command{SchemaVersion: 1, NodeID: "12345678-1234-1234-1234-123456789012", OperationID: "12345678-1234-1234-1234-123456789013", AuthorityEpoch: 1, Generation: 1, CreatedAt: now, DeadlineAt: now.Add(10 * time.Minute), Kind: "agent.config.set", PayloadSHA256: PayloadHash(p), Payload: p}
}
func TestSignedCanonicalCommandAndPinnedKey(t *testing.T) {
	s := testSigner(t)
	pub, e := LoadPublicKey(s.PublicPEM())
	if e != nil {
		t.Fatal(e)
	}
	c := testCommand()
	signed, e := s.Sign(c)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Verify(pub, signed)
	if e != nil || got != c {
		t.Fatal("roundtrip", e)
	}
	other := testSigner(t)
	otherPub, _ := LoadPublicKey(other.PublicPEM())
	if _, e = Verify(otherPub, signed); e == nil {
		t.Fatal("wrong pin accepted")
	}
	var fields map[string]json.RawMessage
	json.Unmarshal([]byte(signed.Body), &fields)
	for key := range fields {
		t.Run(key, func(t *testing.T) {
			changed := strings.Replace(signed.Body, `"`+key+`":`, `"`+key+`":null,"ignored":`, 1)
			x := signed
			x.Body = changed
			if _, e := Verify(pub, x); e == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
	// Even a correctly signed alternate encoding must not become a second meaning.
	raws := []string{" " + signed.Body, signed.Body + "\n", strings.Replace(signed.Body, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), strings.Replace(signed.Body, `"schema_version":1`, `"unknown":1,"schema_version":1`, 1), strings.Replace(signed.Body, `"generation":1`, `"generation":1.0`, 1), strings.Replace(signed.Body, `"agent.config.set"`, `"agent.config.\u0073et"`, 1), strings.Replace(signed.Body, `"schema_version":1,`, "", 1), signed.Body + "{}"}
	for _, raw := range raws {
		sig := ed25519.Sign(s.key, append([]byte(domain), []byte(raw)...))
		if _, e := Verify(pub, nodewire.SignedCommand{Body: raw, Signature: base64.RawURLEncoding.EncodeToString(sig)}); e == nil {
			t.Fatal("noncanonical encoding accepted")
		}
	}
	for _, bad := range []func(*nodewire.Command){func(c *nodewire.Command) { c.AuthorityEpoch = 2 }, func(c *nodewire.Command) { c.Generation = 0 }, func(c *nodewire.Command) {
		c.Payload.HeartbeatIntervalSeconds = 4
		c.PayloadSHA256 = PayloadHash(c.Payload)
	}, func(c *nodewire.Command) {
		c.Payload.HeartbeatIntervalSeconds = 31
		c.PayloadSHA256 = PayloadHash(c.Payload)
	}, func(c *nodewire.Command) { c.DeadlineAt = c.DeadlineAt.Add(time.Second) }} {
		x := c
		bad(&x)
		if _, e := s.Sign(x); e == nil {
			t.Fatal("bounds accepted")
		}
	}
}
func TestSignerPEMStrictAndSeparateKey(t *testing.T) {
	raw, _ := GenerateSigner()
	for _, bad := range [][]byte{append([]byte("junk"), raw...), append(append([]byte{}, raw...), raw...), append([]byte(fmt.Sprintf("-----BEGIN %s-----\ninvalid\n", "PRIVATE KEY")), raw...)} {
		if _, e := LoadSigner(bad); e == nil {
			t.Fatal("malformed bundle accepted")
		}
	}
	s := testSigner(t)
	if _, e := LoadSigner(s.PublicPEM()); e == nil {
		t.Fatal("public accepted as private")
	}
}
