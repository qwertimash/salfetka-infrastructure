package connection

import "strings"

func lines(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }

// ServerStream is called only after validating the complete private configuration.
func (c Configuration) ServerStream() (map[string]any, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	s := c.Public
	if s.Template == Reality {
		return map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"show": false, "target": s.RealityTarget, "serverNames": []string{s.ServerName}, "privateKey": c.Private.RealityPrivateKey, "shortIds": []string{s.RealityShortID}}}, nil
	}
	result := s.transport()
	alpn := []string{"h2", "http/1.1"}
	if s.Template == Hy2 {
		alpn = []string{"h3"}
	}
	result["security"] = "tls"
	result["tlsSettings"] = map[string]any{"alpn": alpn, "certificates": []any{map[string]any{"certificate": lines(c.Private.CertificatePEM), "key": lines(c.Private.KeyPEM)}}}
	return result, nil
}
func (s Spec) transport() map[string]any {
	switch s.Template {
	case GRPC:
		return map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": s.ServiceName, "multiMode": false}}
	case XHTTP:
		return map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": s.Path, "mode": "auto"}}
	case Hy2:
		return map[string]any{"network": "hysteria", "hysteriaSettings": map[string]any{"version": 2}}
	default:
		return map[string]any{"network": "tcp"}
	}
}
func (s Spec) ClientOutbound(credential, trustedCA string) (map[string]any, error) {
	if e := s.Validate(); e != nil {
		return nil, e
	}
	stream := s.transport()
	if s.Template == Reality {
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]any{"serverName": s.ServerName, "fingerprint": "chrome", "password": s.RealityPublicKey, "shortId": s.RealityShortID}
	} else {
		alpn := []string{"h2", "http/1.1"}
		if s.Template == Hy2 {
			alpn = []string{"h3"}
		}
		tls := map[string]any{"serverName": s.ServerName, "allowInsecure": false, "alpn": alpn}
		if trustedCA != "" {
			tls["disableSystemRoot"] = true
			tls["certificates"] = []any{map[string]any{"usage": "verify", "certificate": lines(trustedCA)}}
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	}
	protocol := "vless"
	settings := map[string]any{"vnext": []any{map[string]any{"address": s.Host, "port": s.Port, "users": []any{map[string]any{"id": credential, "encryption": "none"}}}}}
	if s.Template == Hy2 {
		protocol = "hysteria"
		settings = map[string]any{"version": 2, "address": s.Host, "port": s.Port}
		stream["hysteriaSettings"].(map[string]any)["auth"] = credential
	}
	return map[string]any{"tag": "vpn", "protocol": protocol, "settings": settings, "streamSettings": stream}, nil
}
