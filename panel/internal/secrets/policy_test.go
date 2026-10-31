package secrets

import (
	"bytes"
	"testing"
)

func TestPolicyVaultBindingBoundsAndFormatIsolation(t *testing.T) {
	v, _ := New(make([]byte, 32))
	p := bytes.Repeat([]byte("private-policy-fixture"), 1000)
	c, e := v.SealPolicy(p, "node:one:generation:2")
	if e != nil || bytes.Contains(c, p) {
		t.Fatal("encryption")
	}
	got, e := v.OpenPolicy(c, "node:one:generation:2")
	if e != nil || !bytes.Equal(got, p) {
		t.Fatal("roundtrip")
	}
	if _, e = v.OpenPolicy(c, "node:two:generation:2"); e == nil {
		t.Fatal("cross node")
	}
	if _, e = v.Open(c, "node:one:generation:2"); e == nil {
		t.Fatal("policy accepted as credential")
	}
	old, _ := v.Seal([]byte("fixture"), "node:one:generation:2")
	if _, e = v.OpenPolicy(old, "node:one:generation:2"); e == nil {
		t.Fatal("credential accepted as policy")
	}
	c[len(c)-1] ^= 1
	if _, e = v.OpenPolicy(c, "node:one:generation:2"); e == nil {
		t.Fatal("tamper")
	}
	if _, e = v.SealPolicy(make([]byte, MaxPolicyPlaintext+1), "a"); e == nil {
		t.Fatal("oversized")
	}
	var absent *Vault
	if _, e = absent.OpenPolicy(c, "a"); e == nil {
		t.Fatal("missing key")
	}
}
