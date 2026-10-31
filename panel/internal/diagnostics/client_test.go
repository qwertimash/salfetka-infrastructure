package diagnostics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTLSAndRedirectBoundary(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("missing dedicated auth")
		}
		if r.URL.Path != "/panel/v1/testers" {
			t.Error("unexpected path")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"testers":[]}`))
	}))
	defer s.Close()
	c, _ := New(s.URL, secret)
	if _, e := c.Read(context.Background(), "", ""); !errors.Is(e, ErrUnavailable) {
		t.Fatal("untrusted TLS accepted")
	}
	c.http.Transport = s.Client().Transport
	if _, e := c.Read(context.Background(), "", ""); e != nil {
		t.Fatal(e)
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, s.URL, 302) }))
	defer redirect.Close()
	c, _ = New(redirect.URL, secret)
	c.http.Transport = redirect.Client().Transport
	if _, e := c.Read(context.Background(), "", ""); !errors.Is(e, ErrUnavailable) {
		t.Fatal("redirect accepted")
	}
}
func TestValidationAndBounds(t *testing.T) {
	for _, origin := range []string{"http://localhost", strings.Join([]string{"https://", "user", ":", "pass", "@localhost"}, ""), "https://localhost/a", "https://localhost?x=1"} {
		if _, e := New(origin, strings.Repeat("ab", 32)); e == nil {
			t.Fatal(origin)
		}
	}
	for _, pair := range [][2]string{{"../admin", ""}, {"", "1|bad"}, {"https://evil.invalid", ""}} {
		if ValidQuery(pair[0], pair[1]) {
			t.Fatal(pair)
		}
	}
	for _, body := range []string{`[]`, `{"nope":true}`, `{"testers":"` + strings.Repeat("x", MaxResponse) + `"}`} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c, _ := New(s.URL, strings.Repeat("ab", 32))
		c.http.Transport = s.Client().Transport
		if _, e := c.Read(context.Background(), "", ""); e == nil {
			t.Fatal("malformed or oversized accepted")
		}
		s.Close()
	}
	c, _ := New("https://localhost", strings.Repeat("ab", 32))
	transport := c.http.Transport.(*http.Transport)
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS disabled")
	}
	for i := 0; i < 4; i++ {
		c.slots <- struct{}{}
	}
	if _, e := c.Read(context.Background(), "", ""); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unbounded concurrency")
	}
}
