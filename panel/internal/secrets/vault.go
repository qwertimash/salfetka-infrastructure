// Package secrets encrypts private access credentials with a separate installation
// key. Context binding prevents moving ciphertext between users or credentials.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

var ErrUnavailable = errors.New("secret_unavailable")

const MaxPlaintext = 4096

type Vault struct{ aead cipher.AEAD }

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, ErrUnavailable
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Vault{aead: g}, nil
}

func (v *Vault) valid(aad string) bool {
	return v != nil && v.aead != nil && len(aad) > 0 && len(aad) <= 512
}

// Seal stores a format version and a fresh random nonce before the GCM output.
// The caller constructs AAD from immutable owner, device and credential IDs.
func (v *Vault) Seal(plain []byte, aad string) ([]byte, error) {
	if !v.valid(aad) || len(plain) < 1 || len(plain) > MaxPlaintext {
		return nil, ErrUnavailable
	}
	out := make([]byte, 1+v.aead.NonceSize(), 1+v.aead.NonceSize()+len(plain)+v.aead.Overhead())
	out[0] = 1
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, ErrUnavailable
	}
	return v.aead.Seal(out, out[1:], plain, []byte("salfetka-access-secret-v1\x00"+aad)), nil
}

func (v *Vault) Open(encrypted []byte, aad string) ([]byte, error) {
	if !v.valid(aad) {
		return nil, ErrUnavailable
	}
	header := 1 + v.aead.NonceSize()
	if len(encrypted) < header+v.aead.Overhead()+1 || len(encrypted) > header+v.aead.Overhead()+MaxPlaintext || encrypted[0] != 1 {
		return nil, ErrUnavailable
	}
	plain, err := v.aead.Open(nil, encrypted[1:header], encrypted[header:], []byte("salfetka-access-secret-v1\x00"+aad))
	if err != nil {
		return nil, ErrUnavailable
	}
	return plain, nil
}
