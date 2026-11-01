// Package connection defines versioned, typed installation templates shared by
// the panel and a multi-connection node. It never accepts arbitrary engine JSON.
package connection

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Version = 1
const Reality = "vless-tcp-reality"
const Hy2 = "hysteria2"
const GRPC = "vless-grpc-tls"
const XHTTP = "vless-xhttp-tls"

var ErrInvalid = errors.New("connection_invalid")
var ErrPort = errors.New("connection_port_conflict")
var ErrSecrets = errors.New("connection_secrets_invalid")

type Template struct {
	ID             string `json:"id"`
	Version        int    `json:"version"`
	Name           string `json:"name"`
	Network        string `json:"network"`
	DefaultPort    int    `json:"default_port"`
	TLSCertificate bool   `json:"tls_certificate"`
}

func Templates() []Template {
	return []Template{
		{Reality, Version, "TCP Reality", "tcp", 443, false},
		{Hy2, Version, "Hysteria2", "udp", 443, true},
		{GRPC, Version, "gRPC", "tcp", 8443, true},
		{XHTTP, Version, "XHTTP", "tcp", 8444, true},
	}
}
func Lookup(id string) (Template, bool) {
	for _, t := range Templates() {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// Spec contains only public connection parameters. PrivateMaterial travels only
// inside the encrypted database record and the authenticated node channel.
type Spec struct {
	CertificateSource string `json:"certificate_source,omitempty"`
	Template          string `json:"template"`
	Version           int    `json:"version"`
	Host              string `json:"host"`
	ListenIP          string `json:"listen_ip"`
	Port              int    `json:"port"`
	ServerName        string `json:"server_name"`
	ServiceName       string `json:"service_name,omitempty"`
	Path              string `json:"path,omitempty"`
	RealityTarget     string `json:"reality_target,omitempty"`
	RealityPublicKey  string `json:"reality_public_key,omitempty"`
	RealityShortID    string `json:"reality_short_id,omitempty"`
}
type PrivateMaterial struct {
	CertificatePEM    string `json:"certificate_pem,omitempty"`
	KeyPEM            string `json:"key_pem,omitempty"`
	RealityPrivateKey string `json:"reality_private_key,omitempty"`
}
type Configuration struct {
	Public  Spec            `json:"public"`
	Private PrivateMaterial `json:"private"`
}

var label = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var service = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var path = regexp.MustCompile(`^/[a-zA-Z0-9_/-]{1,127}$`)
var short = regexp.MustCompile(`^(?:[0-9a-f]{2}){1,8}$`)

func Host(s string) bool {
	if ip, e := netip.ParseAddr(s); e == nil {
		return ip.Zone() == ""
	}
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if !label.MatchString(p) {
			return false
		}
	}
	return true
}
func (s Spec) Validate() error {
	if s.CertificateSource != "" && s.CertificateSource != "node" {
		return ErrInvalid
	}
	if s.CertificateSource == "node" && s.Template == Reality && s.RealityTarget != "127.0.0.1:8445" {
		return ErrInvalid
	}
	if _, ok := Lookup(s.Template); !ok || s.Version != Version {
		return ErrInvalid
	}
	ip, e := netip.ParseAddr(s.ListenIP)
	if e != nil || ip.Zone() != "" || ip.Is4In6() || !Host(s.Host) || !Host(s.ServerName) || s.Port < 1 || s.Port > 65535 {
		return ErrInvalid
	}
	if s.Template != GRPC && s.ServiceName != "" || s.Template == GRPC && !service.MatchString(s.ServiceName) {
		return ErrInvalid
	}
	if s.Template != XHTTP && s.Path != "" || s.Template == XHTTP && (!path.MatchString(s.Path) || strings.Contains(s.Path, "//")) {
		return ErrInvalid
	}
	if s.Template != Reality {
		if s.RealityTarget != "" || s.RealityPublicKey != "" || s.RealityShortID != "" {
			return ErrInvalid
		}
	} else {
		host, port, e := net.SplitHostPort(s.RealityTarget)
		p, e2 := strconv.Atoi(port)
		if e != nil || e2 != nil || !Host(host) || p < 1 || p > 65535 || !short.MatchString(s.RealityShortID) {
			return ErrInvalid
		}
		key, e := base64.RawURLEncoding.DecodeString(s.RealityPublicKey)
		if e != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != s.RealityPublicKey {
			return ErrInvalid
		}
	}
	return nil
}
func (c Configuration) Validate() error {
	if e := c.Public.Validate(); e != nil {
		return e
	}
	s := c.Private
	if c.Public.Template == Reality {
		if s.CertificatePEM != "" || s.KeyPEM != "" {
			return ErrSecrets
		}
		key, e := base64.RawURLEncoding.DecodeString(s.RealityPrivateKey)
		if e != nil || len(key) != 32 {
			return ErrSecrets
		}
		k, e := ecdh.X25519().NewPrivateKey(key)
		if e != nil || base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()) != c.Public.RealityPublicKey {
			return ErrSecrets
		}
	} else {
		if c.Public.CertificateSource == "node" {
			if s.CertificatePEM != "" || s.KeyPEM != "" || s.RealityPrivateKey != "" {
				return ErrSecrets
			}
			return nil
		}
		if s.RealityPrivateKey != "" || len(s.CertificatePEM) > 32768 || len(s.KeyPEM) > 32768 {
			return ErrSecrets
		}
		pair, e := tls.X509KeyPair([]byte(s.CertificatePEM), []byte(s.KeyPEM))
		if e != nil || len(pair.Certificate) == 0 {
			return ErrSecrets
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil || leaf.VerifyHostname(c.Public.ServerName) != nil {
			return ErrSecrets
		}
	}
	return nil
}
func (s Spec) Network() string {
	if s.Template == Hy2 {
		return "udp"
	}
	return "tcp"
}
func Hash(c Configuration) string {
	b, _ := json.Marshal(c)
	defer clear(b)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Listener struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

func (l Listener) Valid() bool {
	a, e := netip.ParseAddr(l.IP)
	return e == nil && a.Zone() == "" && !a.Is4In6() && l.Port >= 1 && l.Port <= 65535 && (l.Network == "tcp" || l.Network == "udp")
}
func Conflicts(a, b Listener) bool {
	if !a.Valid() || !b.Valid() {
		return true
	}
	if a.Port != b.Port || a.Network != b.Network {
		return false
	}
	x, _ := netip.ParseAddr(a.IP)
	y, _ := netip.ParseAddr(b.IP)
	// IPv6 wildcard can also bind IPv4. Treat it conservatively until the node
	// proves the actual bind; never promise an unreserved OS port.
	if x == netip.IPv6Unspecified() || y == netip.IPv6Unspecified() {
		return true
	}
	return x.Is4() == y.Is4() && (x == y || x.IsUnspecified() || y.IsUnspecified())
}

// Allocate is deterministic and side-effect free. Explicit ports never move.
// The node must still bind-check immediately before applying the configuration.
func Allocate(wanted []Spec, occupied []Listener) ([]Spec, error) {
	if len(wanted) == 0 || len(wanted) > 32 || len(occupied) > 4096 {
		return nil, ErrInvalid
	}
	used := append([]Listener(nil), occupied...)
	for _, l := range used {
		if !l.Valid() {
			return nil, ErrInvalid
		}
	}
	out := append([]Spec(nil), wanted...)
	for i := range out {
		s := &out[i]
		t, ok := Lookup(s.Template)
		if !ok {
			return nil, ErrInvalid
		}
		auto := s.Port == 0
		if auto {
			s.Port = t.DefaultPort
		}
		for {
			if e := s.Validate(); e != nil {
				return nil, e
			}
			l := Listener{s.ListenIP, s.Port, s.Network()}
			busy := false
			for _, u := range used {
				if Conflicts(l, u) {
					busy = true
					break
				}
			}
			if !busy {
				used = append(used, l)
				break
			}
			if !auto || s.Port == 65535 {
				return nil, ErrPort
			}
			s.Port++
		}
	}
	return out, nil
}

// ProfileHash binds a signed access policy to the exact public connection spec.
func ProfileHash(s Spec) string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ReadyAt is a runtime check; historical configuration/signature validation is
// deterministic even after a certificate expires.
func (c Configuration) ReadyAt(now time.Time) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if c.Public.Template == Reality {
		return nil
	}
	// A reference is valid on the wire, but cannot run until the node resolves
	// it to a verified local pair. Never send an empty certificate to an engine.
	if c.Public.CertificateSource == "node" {
		return ErrSecrets
	}
	pair, e := tls.X509KeyPair([]byte(c.Private.CertificatePEM), []byte(c.Private.KeyPEM))
	if e != nil {
		return ErrSecrets
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ErrSecrets
	}
	return nil
}
