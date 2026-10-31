package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/identity"
)

const testOrigin = "https://localhost:18443"
const testPassword = "synthetic-only-password-456"

type fixture struct {
	handler http.Handler
	pool    *pgxpool.Pool
	store   *identity.Store
	logs    *bytes.Buffer
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	p := dbtest.New(t)
	logs := new(bytes.Buffer)
	h, err := New(p, Config{Origin: testOrigin, Logger: slog.New(slog.NewJSONHandler(logs, nil)), BuildVersion: "test-only",
		Static: fstest.MapFS{"index.html": {Data: []byte("<html>shell</html>")}, "assets/app-123.js": {Data: []byte("'use strict';")}}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{h, p, identity.New(p, time.Hour), logs}
}

func call(h http.Handler, method, path, body string, session *identity.Session, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, testOrigin+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("Content-Type", "application/json")
	if method != "GET" && method != "HEAD" {
		r.Header.Set("Origin", testOrigin)
	}
	if session != nil {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: session.Token})
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
	}
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func status(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d safe body=%s", w.Code, want, w.Body.String())
	}
}

func (f fixture) owner(t *testing.T) identity.Session {
	t.Helper()
	token, _ := identity.RandomToken()
	if err := identity.PrepareBootstrap(context.Background(), f.pool, identity.TokenHash(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Bootstrap(context.Background(), token, "owner", testPassword, "local"); err != nil {
		t.Fatal(err)
	}
	session, err := f.store.Login(context.Background(), "owner", testPassword, "local")
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestHTTPSetupCookieCSRFReloadAndLogout(t *testing.T) {
	f := newFixture(t)
	status(t, call(f.handler, "GET", "/api/v1/setup/status", "", nil, nil), 200)
	token, _ := identity.RandomToken()
	if err := identity.PrepareBootstrap(context.Background(), f.pool, identity.TokenHash(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"token":%q,"username":"owner","password":%q}`, token, testPassword)
	status(t, call(f.handler, "POST", "/api/v1/setup", body, nil, map[string]string{"Origin": ""}), 403)
	w := call(f.handler, "POST", "/api/v1/setup", body, nil, nil)
	status(t, w, 201)
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("setup auto-logged in")
	}
	status(t, call(f.handler, "POST", "/api/v1/setup", body, nil, nil), 409)
	status(t, call(f.handler, "GET", "/api/v1/auth/session", "", nil, nil), 401)
	w = call(f.handler, "POST", "/api/v1/auth/login", fmt.Sprintf(`{"username":"owner","password":%q}`, testPassword), nil, nil)
	status(t, w, 200)
	var session identity.Session
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].Name != CookieName {
		t.Fatal("cookie attributes")
	}
	session.Token = cookies[0].Value
	if strings.Contains(w.Body.String(), session.Token) {
		t.Fatal("bearer exposed in response")
	}
	// Two tabs and reload retain the original CSRF token; read endpoints do not rotate it.
	for range 3 {
		read := call(f.handler, "GET", "/api/v1/auth/session", "", &session, nil)
		status(t, read, 200)
		var current identity.Session
		_ = json.Unmarshal(read.Body.Bytes(), &current)
		if current.CSRFToken != session.CSRFToken || len(read.Result().Cookies()) != 0 {
			t.Fatal("GET changed session/CSRF")
		}
	}
	status(t, call(f.handler, "POST", "/api/v1/operations", `{"kind":"system.check"}`, &session, map[string]string{"Idempotency-Key": "tab-a"}), 202)
	status(t, call(f.handler, "POST", "/api/v1/auth/logout", `{}`, &session, map[string]string{"X-CSRF-Token": ""}), 403)
	status(t, call(f.handler, "POST", "/api/v1/auth/logout", `{}`, &session, map[string]string{"Origin": testOrigin + ".evil"}), 403)
	w = call(f.handler, "POST", "/api/v1/auth/logout", `{}`, &session, nil)
	status(t, w, 200)
	if len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
	status(t, call(f.handler, "GET", "/api/v1/auth/session", "", &session, nil), 401)
	for _, secret := range []string{token, session.Token, session.CSRFToken, testPassword, "owner"} {
		if strings.Contains(f.logs.String(), secret) {
			t.Fatal("secret or username in logs")
		}
	}
}

func TestRBACAllFiveRolesAndAdminRevision(t *testing.T) {
	f := newFixture(t)
	owner := f.owner(t)
	ctx := context.Background()
	sessions := []identity.Session{owner}
	for _, role := range []identity.Role{identity.AccessOperator, identity.InfrastructureOperator, identity.Support, identity.Auditor} {
		a, err := f.store.CreateAdmin(ctx, owner.Token, string(role), testPassword, role)
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.Login(ctx, a.Username, testPassword, "local")
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, s)
	}
	for _, session := range sessions {
		t.Run(string(session.User.Role), func(t *testing.T) {
			for _, route := range []string{"/api/v1/overview", "/api/v1/operations"} {
				status(t, call(f.handler, "GET", route, "", &session, nil), 200)
			}
			adminStatus, auditStatus, mutationStatus := 403, 403, 403
			if session.User.Role == identity.Owner {
				adminStatus = 200
			}
			if session.User.Role == identity.Owner || session.User.Role == identity.Auditor {
				auditStatus = 200
			}
			if session.User.Role == identity.Owner || session.User.Role == identity.InfrastructureOperator {
				mutationStatus = 202
			}
			status(t, call(f.handler, "GET", "/api/v1/admins", "", &session, nil), adminStatus)
			status(t, call(f.handler, "GET", "/api/v1/audit", "", &session, nil), auditStatus)
			w := call(f.handler, "POST", "/api/v1/operations", `{"kind":"system.check"}`, &session, map[string]string{"Idempotency-Key": "same-key"})
			status(t, w, mutationStatus)
			if mutationStatus == 202 {
				replay := call(f.handler, "POST", "/api/v1/operations", `{"kind":"system.check"}`, &session, map[string]string{"Idempotency-Key": "same-key"})
				status(t, replay, 202)
				if replay.Body.String() != w.Body.String() || replay.Header().Get("Idempotent-Replayed") != "true" {
					t.Fatal("idempotent HTTP retry")
				}
			}
			if session.User.Role != identity.Owner {
				status(t, call(f.handler, "POST", "/api/v1/admins", `{"username":"forbidden","password":"another-test-password","role":"owner"}`, &session, nil), 403)
				status(t, call(f.handler, "PATCH", "/api/v1/admins/"+owner.User.ID, `{"disabled":true}`, &session, map[string]string{"If-Match": `"1"`}), 403)
			}
		})
	}
	target := sessions[1]
	status(t, call(f.handler, "PATCH", "/api/v1/admins/"+target.User.ID, `{"disabled":true}`, &owner, map[string]string{"If-Match": `"9"`}), 412)
	status(t, call(f.handler, "PATCH", "/api/v1/admins/"+target.User.ID, `{"disabled":true}`, &owner, map[string]string{"If-Match": `"1"`}), 200)
	status(t, call(f.handler, "GET", "/api/v1/auth/session", "", &target, nil), 401)
	status(t, call(f.handler, "PATCH", "/api/v1/admins/"+owner.User.ID, `{"role":"support"}`, &owner, map[string]string{"If-Match": `"1"`}), 409)
}

func TestStrictJSONRoutesAndSafeErrors(t *testing.T) {
	f := newFixture(t)
	for _, body := range []string{
		`null`, `[]`, `{}`, `{"username":"x","password":"x","unknown":"secret"}`,
		`{"username":"x","username":"y","password":"x"}`, `{"Username":"x","password":"x"}`,
		`{"username":null,"password":"x"}`, `{"username":"x","password":"x"} {}`,
		`{"username":"x","password":"` + strings.Repeat("x", MaxBodyBytes) + `"}`,
		"{\"username\":\"\xff\",\"password\":\"x\"}",
	} {
		status(t, call(f.handler, "POST", "/api/v1/auth/login", body, nil, nil), 400)
	}
	status(t, call(f.handler, "POST", "/api/v1/auth/login", `{}`, nil, map[string]string{"Content-Type": "text/plain"}), 415)
	for _, route := range []string{"/api/no-such-route", "/api", "/api/v1/admins/not-a-uuid", "/missing", "/.env", "/assets/../.env"} {
		w := call(f.handler, "GET", route, "", nil, nil)
		status(t, w, 404)
		if !strings.Contains(w.Body.String(), `"code":"not_found"`) || strings.Contains(w.Body.String(), "shell") {
			t.Fatal("API/static fallback or unsafe error")
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		for _, route := range []string{"/nodes", "/diagnostics"} {
			w := call(f.handler, method, route, "", nil, nil)
			status(t, w, 200)
			if !strings.Contains(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-store" || (method == "GET" && !strings.Contains(w.Body.String(), "shell")) || (method == "HEAD" && w.Body.Len() != 0) {
				t.Fatalf("page deep link %s must serve the safe shell", route)
			}
		}
	}
	status(t, call(f.handler, "PUT", "/api/v1/auth/login", `{}`, nil, nil), 405)
	w := call(f.handler, "GET", "/", "", nil, nil)
	status(t, w, 200)
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("shell security/cache headers")
	}
	w = call(f.handler, "GET", "/assets/app-123.js", "", nil, nil)
	status(t, w, 200)
	if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("asset cache")
	}
}

func TestExpiryIPRateLimitIgnoresForwardingAndDatabaseFailure(t *testing.T) {
	f := newFixture(t)
	session := f.owner(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, "UPDATE admin_sessions SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	status(t, call(f.handler, "GET", "/api/v1/auth/session", "", &session, nil), 401)
	if _, err := f.pool.Exec(ctx, "INSERT INTO identity_rate_limits(bucket_hash,attempts) VALUES($1,50)", identity.TokenHash("login:ip:192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		h, _ := New(f.pool, Config{Origin: testOrigin})
		w := call(h, "POST", "/api/v1/auth/login", `{"username":"owner","password":"test-only"}`, nil, map[string]string{"X-Forwarded-For": "192.0.2.2", "Forwarded": "for=192.0.2.3"})
		status(t, w, 429)
		if w.Header().Get("Retry-After") != "900" {
			t.Fatal("missing retry hint")
		}
	}
	f.pool.Close()
	status(t, call(f.handler, "GET", "/healthz", "", nil, nil), 200)
	status(t, call(f.handler, "GET", "/readyz", "", nil, nil), 503)
	w := call(f.handler, "GET", "/api/v1/auth/session", "", &session, nil)
	status(t, w, 503)
	if strings.Contains(w.Body.String(), "closed") || strings.Contains(w.Body.String(), "SELECT") || strings.Contains(w.Body.String(), session.Token) {
		t.Fatal("raw database/credential error")
	}
}

func TestReadinessAndHTTPSConfiguration(t *testing.T) {
	p := dbtest.NewUnmigrated(t)
	h, err := New(p, Config{Origin: testOrigin})
	if err != nil {
		t.Fatal(err)
	}
	status(t, call(h, "GET", "/healthz", "", nil, nil), 200)
	status(t, call(h, "GET", "/readyz", "", nil, nil), 503)
	for _, origin := range []string{"", "http://localhost", "https://localhost/", "https://synthetic-user@localhost", "https://localhost?x=1", "https://localhost#x"} {
		if _, err := New(p, Config{Origin: origin}); err == nil {
			t.Fatal("unsafe Origin config accepted")
		}
	}
}
