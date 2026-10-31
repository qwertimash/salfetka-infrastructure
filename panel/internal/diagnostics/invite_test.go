package diagnostics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInvitationTLSRetryAndFixedEndpoint(t *testing.T) {
	key := strings.Repeat("ca", 32)
	account := "10000000-0000-4000-8000-000000000001"
	codes := []string{}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/panel/v1/invitations" || r.Header.Get("Authorization") != "Bearer "+key {
			t.Error("wrong boundary")
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		codes = append(codes, body["code"])
		if body["account_id"] != account {
			t.Error("wrong account")
		}
		w.Write([]byte(`{"tester_id":"` + account + `","expires_at_ms":123456}`))
	}))
	defer s.Close()
	c, _ := New(s.URL, key)
	if _, e := c.Invite(context.Background(), account, "Tester", "retry-request-00001"); e == nil {
		t.Fatal("untrusted TLS accepted")
	}
	c.http.Transport = s.Client().Transport
	for i := 0; i < 2; i++ {
		r, e := c.Invite(context.Background(), account, "Tester", "retry-request-00001")
		if e != nil || len(r.Code) != 64 {
			t.Fatal(e)
		}
	}
	if len(codes) != 2 || codes[0] != codes[1] {
		t.Fatal("unstable retry")
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, s.URL, 307) }))
	defer redirect.Close()
	c, _ = New(redirect.URL, key)
	c.http.Transport = redirect.Client().Transport
	if _, e := c.Invite(context.Background(), account, "Tester", "retry-request-00001"); e == nil {
		t.Fatal("redirect accepted")
	}
	if len(codes) != 2 {
		t.Fatal("redirect forwarded write key")
	}
}
