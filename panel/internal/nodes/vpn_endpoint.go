package nodes

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/url"
	"regexp"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/roomroute"
	"strconv"
	"strings"
)

// Public connection metadata, never an arbitrary engine configuration.
type VPNEndpoint struct {
	Connection     *connection.Spec `json:"connection,omitempty"`
	PersonalRooms  bool             `json:"personal_rooms,omitempty"`
	AccountSession bool             `json:"account_session,omitempty"`
	Backend        string           `json:"backend,omitempty"`
	Provider       string           `json:"provider,omitempty"`
	Transport      string           `json:"transport,omitempty"`
	Room           string           `json:"room,omitempty"`
	BootstrapDNS   string           `json:"bootstrap_dns,omitempty"`
	Host           string           `json:"host"`
	Port           int              `json:"port"`
	ServerName     string           `json:"server_name"`
	TrustedCAPEM   string           `json:"trusted_ca_pem,omitempty"`
}

var dnsLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func validVPNHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func (e VPNEndpoint) Valid() bool {
	if !nodewire.ValidBackend(e.Backend) {
		return false
	}
	if e.Backend == nodewire.BackendOLCRTC {
		if e.PersonalRooms {
			if !e.AccountSession {
				return false
			}
			if _, err := roomroute.URL(e.Room, strings.Repeat("a", 64)); err != nil {
				return false
			}
		}
		if e.Connection != nil || e.Host != "" || e.Port != 0 || e.ServerName != "" || e.TrustedCAPEM != "" {
			return false
		}
		if e.Provider != "jitsi" {
			return false
		}
		if e.Transport != "vp8channel" {
			return false
		}
		u, err := url.Parse(e.Room)
		if err != nil || u.Scheme != "https" || u.User != nil || !validVPNHost(u.Hostname()) || len(e.Room) > 8192 {
			return false
		}
		host, port, err := net.SplitHostPort(e.BootstrapDNS)
		n, e2 := strconv.Atoi(port)
		return err == nil && e2 == nil && net.ParseIP(host) != nil && n > 0 && n <= 65535
	}
	if e.PersonalRooms || e.AccountSession || e.Provider != "" || e.Transport != "" || e.Room != "" || e.BootstrapDNS != "" {
		return false
	}
	minimumPort := 1024
	if e.Connection != nil {
		c := e.Connection
		if c.Validate() != nil || c.Host != e.Host || c.Port != e.Port || c.ServerName != e.ServerName || (c.Template == connection.Hy2) != (e.Backend == "hysteria2") {
			return false
		}
		if c.Template == connection.Reality && e.TrustedCAPEM != "" {
			return false
		}
		minimumPort = 1
	}
	if !validVPNHost(e.Host) || !validVPNHost(e.ServerName) || e.Port < minimumPort || e.Port > 65535 || len(e.TrustedCAPEM) > 16384 {
		return false
	}
	if e.TrustedCAPEM != "" {
		b, rest := pem.Decode([]byte(e.TrustedCAPEM))
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
			return false
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return false
		}
	}
	return true
}

func (e *VPNEndpoint) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return ErrInvalid
		}
		switch key {
		case "connection", "personal_rooms", "account_session", "backend", "provider", "transport", "room", "bootstrap_dns", "host", "port", "server_name", "trusted_ca_pem":
		default:
			return ErrInvalid
		}
		seen[key] = true
		var part json.RawMessage
		if d.Decode(&part) != nil || bytes.Equal(part, []byte("null")) {
			return ErrInvalid
		}
	}
	if _, err = d.Token(); err != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	type plain VPNEndpoint
	var result plain
	if json.Unmarshal(raw, &result) != nil {
		return ErrInvalid
	}
	if result.Backend != nodewire.BackendOLCRTC && (!seen["host"] || !seen["port"] || !seen["server_name"]) {
		return ErrInvalid
	}
	*e = VPNEndpoint(result)
	return nil
}

func (e VPNEndpoint) Engine() string {
	if e.Backend == "olcrtc" {
		return "olcrtc"
	}
	return "xray"
}

func (e VPNEndpoint) ProfileSHA256() string {
	if e.Connection != nil {
		return connection.ProfileHash(*e.Connection)
	}
	if e.Backend != "olcrtc" {
		return ""
	}
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
