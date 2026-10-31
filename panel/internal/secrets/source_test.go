package secrets

import (
	"bytes"
	"testing"
)

func TestSourceEncryptionDomainAndLargePayload(t *testing.T) {
	v, _ := New(bytes.Repeat([]byte{4}, 32))
	raw := bytes.Repeat([]byte{'x'}, 512*1024)
	c, e := v.SealSource(raw, "source:a")
	if e != nil {
		t.Fatal(e)
	}
	out, e := v.OpenSource(c, "source:a")
	if e != nil || !bytes.Equal(raw, out) {
		t.Fatal("source roundtrip")
	}
	if _, e = v.OpenSource(c, "source:b"); e == nil {
		t.Fatal("AAD")
	}
	if _, e = v.OpenPolicy(c, "source:a"); e == nil {
		t.Fatal("policy domain")
	}
	small, _ := v.Seal([]byte("hello"), "source:a")
	if _, e = v.OpenSource(small, "source:a"); e == nil {
		t.Fatal("credential domain")
	}
	c[len(c)-1] ^= 1
	if _, e = v.OpenSource(c, "source:a"); e == nil {
		t.Fatal("tamper")
	}
}
