// Package appconfig loads explicit panel settings without reading bot config or
// logging secret values. Production commands use file-based secrets.
package appconfig

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/secrets"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func LoadNodeSigner() (*nodecontrol.Signer, error) {
	b, err := PrivateFile(os.Getenv("PANEL_NODE_SIGNER_FILE"))
	if err != nil {
		return nil, errors.New("node_signer_required_or_invalid")
	}
	signer, err := nodecontrol.LoadSigner(b)
	if err != nil {
		return nil, errors.New("node_signer_required_or_invalid")
	}
	return signer, nil
}

func LoadNodeAuthority() (*nodes.Authority, error) {
	b, err := PrivateFile(os.Getenv("PANEL_NODE_AUTHORITY_FILE"))
	if err != nil {
		return nil, errors.New("node_authority_required_or_invalid")
	}
	authority, err := nodes.LoadAuthority(b)
	if err != nil {
		return nil, errors.New("node_authority_required_or_invalid")
	}
	return authority, nil
}

func LoadVault() (*secrets.Vault, error) {
	b, e := PrivateFile(os.Getenv("PANEL_MASTER_KEY_FILE"))
	if e != nil {
		return nil, errors.New("master_key_required_or_invalid")
	}
	key, e := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(key) != 32 {
		return nil, errors.New("master_key_required_or_invalid")
	}
	return secrets.New(key)
}

type API struct {
	Listen, Origin, CertFile, KeyFile, StaticDir string
	SubscriptionOrigin                           string
	NodeInstallOrigin                            string
	DeliveryOnly                                 bool
	SessionTTL                                   time.Duration
}

// HTTPSOrigin accepts a canonical origin, never credentials or a URL path.
func HTTPSOrigin(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.Path == "" && u.RawQuery == "" && !u.ForceQuery &&
		u.Fragment == "" && u.String() == value && !strings.Contains(value, "#")
}

func PrivateFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("secret_file_required")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errors.New("secret_file_unreadable")
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Size() < 1 || s.Size() > 65536 {
		return nil, errors.New("secret_file_permissions_or_size")
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || int64(len(b)) != s.Size() {
		return nil, errors.New("secret_file_read_failed")
	}
	return b, nil
}

func DatabaseURL() (string, error) {
	raw, e := PrivateFile(os.Getenv("PANEL_DATABASE_URL_FILE"))
	if e != nil {
		return "", e
	}
	dsn := strings.TrimSpace(string(raw))
	u, e := url.Parse(dsn)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.Path == "" || u.Fragment != "" {
		return "", errors.New("database_url_invalid")
	}
	// pgx accepts host/user/service overrides in query parameters. Keep the
	// checked endpoint authoritative and reject ambiguous duplicate settings.
	query, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return "", errors.New("database_url_invalid")
	}
	for key, values := range query {
		if len(values) != 1 {
			return "", errors.New("database_url_invalid")
		}
		switch key {
		case "sslmode", "sslrootcert", "sslcert", "sslkey", "connect_timeout":
		default:
			return "", errors.New("database_url_invalid")
		}
	}
	// No default prefer/fallback TLS. Plaintext requires an explicit local-only mode.
	if query.Get("sslmode") != "verify-full" {
		ip := net.ParseIP(u.Hostname())
		local := (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" || u.Hostname() == "postgres"
		if os.Getenv("PANEL_ALLOW_LOCAL_DB_PLAINTEXT") != "1" || !local || query.Get("sslmode") != "disable" {
			return "", errors.New("database_tls_required")
		}
	}
	return dsn, nil
}

func LoadAPI() (API, error) {
	c := API{Listen: os.Getenv("PANEL_LISTEN_ADDR"), Origin: os.Getenv("PANEL_PUBLIC_ORIGIN"),
		CertFile: os.Getenv("PANEL_TLS_CERT_FILE"), KeyFile: os.Getenv("PANEL_TLS_KEY_FILE"),
		StaticDir: os.Getenv("PANEL_WEB_DIR"), SessionTTL: 8 * time.Hour}
	switch os.Getenv("PANEL_API_MODE") {
	case "", "admin":
	case "delivery":
		c.DeliveryOnly = true
	default:
		return c, errors.New("api_mode_invalid")
	}
	c.NodeInstallOrigin = os.Getenv("PANEL_NODE_INSTALL_ORIGIN")
	if c.NodeInstallOrigin != "" && !HTTPSOrigin(c.NodeInstallOrigin) {
		return c, errors.New("node_install_origin_invalid")
	}
	c.SubscriptionOrigin = os.Getenv("PANEL_SUBSCRIPTION_ORIGIN")
	if c.SubscriptionOrigin == "" {
		c.SubscriptionOrigin = c.Origin
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:18443"
	}
	if _, _, e := net.SplitHostPort(c.Listen); e != nil {
		return c, errors.New("listen_address_invalid")
	}
	if !HTTPSOrigin(c.Origin) || !HTTPSOrigin(c.SubscriptionOrigin) {
		return c, errors.New("https_origin_required")
	}
	if c.CertFile == "" || c.KeyFile == "" || (!c.DeliveryOnly && c.StaticDir == "") {
		return c, errors.New("tls_and_web_files_required")
	}
	if s := os.Getenv("PANEL_SESSION_TTL_SECONDS"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 60 || n > 86400 {
			return c, errors.New("session_ttl_invalid")
		}
		c.SessionTTL = time.Duration(n) * time.Second
	}
	return c, nil
}
