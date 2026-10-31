package secrets

import "crypto/rand"

// Signed VPN envelopes contain wire credentials. Keep their storage format and
// authentication domain separate from the bounded B2 credential format.
const MaxPolicyPlaintext = 128 * 1024

func (v *Vault) SealPolicy(plain []byte, aad string) ([]byte, error) {
	if !v.valid(aad) || len(plain) == 0 || len(plain) > MaxPolicyPlaintext {
		return nil, ErrUnavailable
	}
	out := make([]byte, 1+v.aead.NonceSize())
	out[0] = 2
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, ErrUnavailable
	}
	return v.aead.Seal(out, out[1:], plain, []byte("salfetka-vpn-policy-at-rest-v1\x00"+aad)), nil
}
func (v *Vault) OpenPolicy(encrypted []byte, aad string) ([]byte, error) {
	if !v.valid(aad) {
		return nil, ErrUnavailable
	}
	header := 1 + v.aead.NonceSize()
	if len(encrypted) < header+v.aead.Overhead()+1 || len(encrypted) > header+v.aead.Overhead()+MaxPolicyPlaintext || encrypted[0] != 2 {
		return nil, ErrUnavailable
	}
	plain, err := v.aead.Open(nil, encrypted[1:header], encrypted[header:], []byte("salfetka-vpn-policy-at-rest-v1\x00"+aad))
	if err != nil {
		return nil, ErrUnavailable
	}
	return plain, nil
}
