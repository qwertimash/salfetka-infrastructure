package antifraud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControllerTLSProjectionReleaseAndErrors(t *testing.T) {
	mode := "page"
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("k", 64) {
			t.Error("missing credential")
		}
		switch mode {
		case "page":
			fmt.Fprint(w, `{"items":[],"next_cursor":"","generated_at_ms":1000,"coverage_scope":"declared_client_ingress_meters_only","aggregate_bps":1000000,"claim_token":"should-not-cross"}`)
		case "release":
			if r.Method != "POST" || r.URL.Path != "/admin/release" {
				t.Error("wrong action")
			}
			fmt.Fprint(w, `{"released":false}`)
		case "conflict":
			w.WriteHeader(409)
		case "redirect":
			http.Redirect(w, r, "https://untrusted.invalid/token", 302)
		case "wrong":
			fmt.Fprint(w, `{"items":[],"generated_at_ms":1000}`)
		}
	}))
	defer server.Close()
	c, err := New(server.URL, strings.Repeat("k", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Read(context.Background(), ""); err != ErrUnavailable {
		t.Fatal("untrusted cert accepted", err)
	}
	c.http.Transport = server.Client().Transport // trust only this ephemeral test cert
	page, err := c.Read(context.Background(), "")
	if err != nil || page.Items == nil {
		t.Fatal(page, err)
	}
	mode = "release"
	changed, err := c.Release(context.Background(), "account", 1, "owner")
	if changed || err != nil {
		t.Fatal(changed, err)
	}
	before := calls
	if _, err = c.Release(context.Background(), "../bad", 1, "owner"); err != ErrInvalid || calls != before {
		t.Fatal("bad identity reached controller")
	}
	for _, m := range []string{"conflict", "redirect", "wrong"} {
		mode = m
		_, err = c.Read(context.Background(), "")
		want := ErrUnavailable
		if m == "conflict" {
			want = ErrConflict
		}
		if err != want {
			t.Fatal(m, err)
		}
	}
}
func TestRejectInvalidConfiguration(t *testing.T) {
	for _, origin := range []string{"http://localhost", "https://user:pass@localhost", "https://localhost/admin", "https://localhost?token=x"} {
		if _, err := New(origin, strings.Repeat("k", 64)); err == nil {
			t.Fatal(origin)
		}
	}
	if _, err := New("https://localhost", strings.Repeat("k", 63)+"\n"); err == nil {
		t.Fatal("header injection")
	}
}
