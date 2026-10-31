package appconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secret(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if e := os.WriteFile(p, []byte(s), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestSecretFilesFailClosed(t *testing.T) {
	p := secret(t, "synthetic-sensitive-value")
	b, e := PrivateFile(p)
	if e != nil || string(b) != "synthetic-sensitive-value" {
		t.Fatal("read failed")
	}
	if e = os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = PrivateFile(p); e == nil || strings.Contains(e.Error(), "synthetic") {
		t.Fatal("permissive secret accepted or leaked")
	}
	target := secret(t, "another")
	link := filepath.Join(t.TempDir(), "link")
	if e = os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if _, e = PrivateFile(link); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestDatabaseRequiresExplicitSecureTransport(t *testing.T) {
	for _, tc := range []struct {
		url, allow string
		ok         bool
	}{
		{"postgres://a:b@db.example.invalid/panel?sslmode=verify-full", "", true},
		{"postgres://a:b@127.0.0.1/panel?sslmode=disable", "1", true},
		{"postgres://a:b@127.0.0.1/panel?sslmode=disable", "", false},
		{"postgres://a:b@db.example.invalid/panel?sslmode=disable", "1", false},
		{"postgres://a:b@db.example.invalid/panel?sslmode=prefer", "", false},
		{"postgres://a:b@db.example.invalid/panel?sslmode=verify-full&sslmode=disable", "", false},
		{"postgres://a:b@127.0.0.1/panel?sslmode=disable&host=db.example.invalid", "1", false},
		{"postgres://a:b@db.example.invalid/panel?sslmode=verify-full&ssl=true", "", false},
		{"postgres://a:b@db.example.invalid/panel?sslmode=verify-full&service=other", "", false},
	} {
		t.Setenv("PANEL_DATABASE_URL_FILE", secret(t, tc.url))
		t.Setenv("PANEL_ALLOW_LOCAL_DB_PLAINTEXT", tc.allow)
		_, e := DatabaseURL()
		if (e == nil) != tc.ok {
			t.Fatalf("TLS expectation failed")
		}
	}
}
func TestOriginAndSessionBounds(t *testing.T) {
	t.Setenv("PANEL_PUBLIC_ORIGIN", "https://localhost:18443")
	t.Setenv("PANEL_TLS_CERT_FILE", "cert")
	t.Setenv("PANEL_TLS_KEY_FILE", "key")
	t.Setenv("PANEL_WEB_DIR", "web")
	if _, e := LoadAPI(); e != nil {
		t.Fatal(e)
	}
	for _, o := range []string{"http://localhost", "https://example.invalid/path", "https://synthetic-user@example.invalid", "https://example.invalid?key=value"} {
		t.Setenv("PANEL_PUBLIC_ORIGIN", o)
		if _, e := LoadAPI(); e == nil {
			t.Fatal("bad origin accepted")
		}
	}
	t.Setenv("PANEL_PUBLIC_ORIGIN", "https://localhost:18443")
	t.Setenv("PANEL_SESSION_TTL_SECONDS", "0")
	if _, e := LoadAPI(); e == nil {
		t.Fatal("unbounded session accepted")
	}
}

func TestDeliveryConfigurationKeepsPrivateAdminOrigin(t *testing.T) {
	t.Setenv("PANEL_PUBLIC_ORIGIN", "https://localhost:18443")
	t.Setenv("PANEL_TLS_CERT_FILE", "cert")
	t.Setenv("PANEL_TLS_KEY_FILE", "key")
	t.Setenv("PANEL_WEB_DIR", "web")
	t.Setenv("PANEL_API_MODE", "admin")
	t.Setenv("PANEL_SUBSCRIPTION_ORIGIN", "")
	c, err := LoadAPI()
	if err != nil || c.SubscriptionOrigin != c.Origin || c.DeliveryOnly {
		t.Fatal("legacy configuration changed")
	}
	t.Setenv("PANEL_SUBSCRIPTION_ORIGIN", "https://subscriptions.example.test")
	c, err = LoadAPI()
	if err != nil || c.Origin != "https://localhost:18443" || c.SubscriptionOrigin != "https://subscriptions.example.test" {
		t.Fatal("origins were not separated")
	}
	for _, origin := range []string{"http://example.test", "https://example.test/", "https://example.test?", "https://example.test#", "https://a@example.test", "https://example.test/s/secret", "https://"} {
		t.Setenv("PANEL_SUBSCRIPTION_ORIGIN", origin)
		if _, err := LoadAPI(); err == nil {
			t.Fatal("invalid subscription origin accepted")
		}
	}
	t.Setenv("PANEL_SUBSCRIPTION_ORIGIN", "https://subscriptions.example.test")
	t.Setenv("PANEL_API_MODE", "public")
	if _, err := LoadAPI(); err == nil {
		t.Fatal("unknown API mode accepted")
	}
	t.Setenv("PANEL_API_MODE", "delivery")
	t.Setenv("PANEL_WEB_DIR", "")
	c, err = LoadAPI()
	if err != nil || !c.DeliveryOnly {
		t.Fatal("delivery unnecessarily requires static/admin files")
	}
}
