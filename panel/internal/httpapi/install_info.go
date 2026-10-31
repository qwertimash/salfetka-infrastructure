package httpapi

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"salfetka/panel/internal/nodes"
	"time"
)

// Trust material is served only to infrastructure operators. The installer code
// comes from their authenticated panel; it never trusts an HTTP-discovered key.
func (a *api) installInfo() (any, error) {
	raw := a.config.NodeInstallCA
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(raw) > 32768 || a.config.NodeSigner == nil {
		return nil, nodes.ErrKey
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	origin := a.config.NodeInstallOrigin
	if origin == "" {
		origin = a.config.Origin
	}
	u, e2 := url.Parse(origin)
	if e != nil || e2 != nil || cert.VerifyHostname(u.Hostname()) != nil || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return nil, nodes.ErrKey
	}
	return map[string]any{"schema": 1, "panel_url": origin, "ca_pem": string(raw), "signer_pem": string(a.config.NodeSigner.PublicPEM())}, nil
}
