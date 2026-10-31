package nodevpn

import "crypto/tls"

// LoadTLSMaterial reads regular, non-symlink files. The private key must be owned
// by this service account and inaccessible to other users.
func LoadTLSMaterial(certPath, keyPath string) (string, string, error) {
	cert, err := readExternal(certPath, false)
	if err != nil {
		return "", "", err
	}
	key, err := readExternal(keyPath, true)
	if err != nil {
		return "", "", err
	}
	defer clear(key)
	if _, err = tls.X509KeyPair(cert, key); err != nil {
		return "", "", fault("vpn_tls_invalid")
	}
	return string(cert), string(key), nil
}
