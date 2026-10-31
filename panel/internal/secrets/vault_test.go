package secrets

import (
	"bytes"
	"errors"
	"testing"
)

func TestVaultBindsOwnerAndCredentialAndAuthenticatesCiphertext(t *testing.T) {
	v, e := New(bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	plain := []byte("synthetic-device-credential")
	aad := "owner-a/device-a/credential-a/revision-1"
	c, e := v.Seal(plain, aad)
	if e != nil {
		t.Fatal(e)
	}
	c2, e := v.Seal(plain, aad)
	if e != nil || bytes.Equal(c, c2) || bytes.Contains(c, plain) {
		t.Fatal("nonce reuse or exposed secret")
	}
	p, e := v.Open(c, aad)
	if e != nil || !bytes.Equal(p, plain) {
		t.Fatal("round trip failed")
	}
	if _, e = v.Open(c, "owner-b/device-a/credential-a/revision-1"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("cross-user ciphertext accepted")
	}
	if _, e = v.Open(c, "owner-a/device-a/credential-b/revision-1"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("cross-credential ciphertext accepted")
	}
	other, _ := New(bytes.Repeat([]byte{8}, 32))
	if _, e = other.Open(c, aad); !errors.Is(e, ErrUnavailable) {
		t.Fatal("wrong installation key accepted")
	}
	for i := range c {
		bad := append([]byte(nil), c...)
		bad[i] ^= 0x01
		if _, e = v.Open(bad, aad); !errors.Is(e, ErrUnavailable) {
			t.Fatalf("tampering accepted at byte %d", i)
		}
	}
}

func TestVaultFailClosedBoundsAndMissingKey(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, e := New(make([]byte, n)); e == nil {
			t.Fatal("invalid key size accepted")
		}
	}
	v, _ := New(make([]byte, 32))
	for _, p := range [][]byte{nil, make([]byte, MaxPlaintext+1)} {
		if _, e := v.Seal(p, "a"); e == nil {
			t.Fatal("bad plaintext bound accepted")
		}
	}
	if _, e := v.Seal([]byte("a"), ""); e == nil {
		t.Fatal("missing context accepted")
	}
	for _, c := range [][]byte{nil, make([]byte, 5), make([]byte, MaxPlaintext+50)} {
		if _, e := v.Open(c, "a"); e == nil {
			t.Fatal("bad ciphertext accepted")
		}
	}
	var missing *Vault
	if _, e := missing.Seal([]byte("a"), "a"); e == nil {
		t.Fatal("missing vault accepted")
	}
	if _, e := missing.Open([]byte("a"), "a"); e == nil {
		t.Fatal("missing vault accepted")
	}
}
