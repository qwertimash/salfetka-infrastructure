package secrets

import "crypto/rand"

// Source documents use a separate authenticated domain. The larger limit also
// covers the private provenance envelope; it does not enlarge access secrets.
const MaxSourcePlaintext = 4 * 1024 * 1024

func (v *Vault) SealSource(plain []byte, aad string) ([]byte, error) {
	if !v.valid(aad) || len(plain) == 0 || len(plain) > MaxSourcePlaintext {
		return nil, ErrUnavailable
	}
	out := make([]byte, 1+v.aead.NonceSize())
	out[0] = 3
	if _, e := rand.Read(out[1:]); e != nil {
		return nil, ErrUnavailable
	}
	return v.aead.Seal(out, out[1:], plain, []byte("salfetka-source-v1\x00"+aad)), nil
}
func (v *Vault) OpenSource(encrypted []byte, aad string) ([]byte, error) {
	if !v.valid(aad) {
		return nil, ErrUnavailable
	}
	h := 1 + v.aead.NonceSize()
	if len(encrypted) < h+v.aead.Overhead()+1 || len(encrypted) > h+v.aead.Overhead()+MaxSourcePlaintext || encrypted[0] != 3 {
		return nil, ErrUnavailable
	}
	b, e := v.aead.Open(nil, encrypted[1:h], encrypted[h:], []byte("salfetka-source-v1\x00"+aad))
	if e != nil {
		return nil, ErrUnavailable
	}
	return b, nil
}
