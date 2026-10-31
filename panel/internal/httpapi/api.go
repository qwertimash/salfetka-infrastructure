package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/antifraud"
	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/catalog"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/diagnostics"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/jobs"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
)

const CookieName = "__Host-salfetka_session"
const MaxBodyBytes = 32 * 1024

var deliveryPath = regexp.MustCompile(`^/(s|a|i)/[A-Za-z0-9_-]{43}$`)

type Config struct {
	Antifraud          antifraud.Service
	Diagnostics        diagnostics.Reader
	DiagnosticsInviter diagnostics.Inviter
	Origin             string
	SubscriptionOrigin string
	DeliveryOnly       bool
	Static             fs.FS
	SessionTTL         time.Duration
	Logger             *slog.Logger
	BuildVersion       string
	Vault              *secrets.Vault
	NodeAuthority      *nodes.Authority
	NodeSigner         *nodecontrol.Signer
	NodeInstallCA      []byte
	NodeInstallOrigin  string
}

type api struct {
	pool              *pgxpool.Pool
	identity          *identity.Store
	access            *access.Store
	nodes             *nodes.Store
	jobs              *jobs.Store
	releases          *releases.Store
	catalog           *catalog.Store
	importSlots       chan struct{}
	subscriptionSlots chan struct{}
	config            Config
}

func New(pool *pgxpool.Pool, config Config) (http.Handler, error) {
	u, err := url.Parse(config.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.String() != config.Origin || pool == nil {
		return nil, errors.New("invalid_api_configuration")
	}
	if config.NodeInstallOrigin != "" && !appconfig.HTTPSOrigin(config.NodeInstallOrigin) {
		return nil, errors.New("node_install_origin_invalid")
	}
	if config.SubscriptionOrigin == "" {
		config.SubscriptionOrigin = config.Origin
	}
	if !appconfig.HTTPSOrigin(config.Origin) || !appconfig.HTTPSOrigin(config.SubscriptionOrigin) {
		return nil, errors.New("invalid_api_configuration")
	}
	if config.SessionTTL < 0 || config.SessionTTL > 24*time.Hour {
		return nil, errors.New("invalid_api_configuration")
	}
	nodeStore := nodes.New(pool, config.Vault, config.NodeAuthority)
	nodeStore.Signer = config.NodeSigner
	return &api{releases: releases.New(pool, config.Vault, nodeStore), pool: pool, identity: identity.New(pool, config.SessionTTL), jobs: jobs.New(pool), access: access.New(pool, config.Vault), nodes: nodeStore, catalog: catalog.New(pool, config.Vault), subscriptionSlots: make(chan struct{}, 4), importSlots: make(chan struct{}, 4), config: config}, nil
}

type response struct {
	http.ResponseWriter
	status int
}

func (w *response) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *response) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (a *api) ServeHTTP(out http.ResponseWriter, request *http.Request) {
	w := &response{ResponseWriter: out}
	id, err := identity.RandomToken()
	if err != nil {
		id = "unavailable"
	}
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	defer func() {
		if recover() != nil {
			writeError(w, http.StatusInternalServerError, "internal_error")
		}
		if a.config.Logger != nil {
			// No URL, headers, body, principal, SQL error or panic value enters logs.
			a.config.Logger.Info("http_request", "request_id", id, "status", w.status)
		}
	}()
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	r := request.WithContext(ctx)
	// This gate precedes every route, including static/setup/agent handlers.
	// A valid admin cookie or forwarded header never changes the listener's role.
	if a.config.DeliveryOnly && (r.URL.RawPath != "" || (r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && !deliveryPath.MatchString(r.URL.Path))) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.URL.Path == "/healthz" {
		if !method(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/readyz" {
		if !method(w, r, http.MethodGet) {
			return
		}
		if database.Ready(ctx, a.pool) != nil {
			writeError(w, 503, "unavailable")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready"})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/i/") {
		a.serveDeviceInvite(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/managed/") {
		a.serveManaged(w, r)
		return
	}
	if a.serveManagedNode(w, r) {
		return
	}
	if r.URL.Path == "/api/v1/servers" || strings.HasPrefix(r.URL.Path, "/api/v1/servers/") {
		a.serveServers(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/a/") {
		a.serveAssignmentResolve(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/s/") {
		a.serveSubscription(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/diagnostics/") {
		a.serveDiagnostics(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/antifraud/") {
		a.serveAntifraud(w, r)
		return
	}
	if r.URL.Path == "/api/v1/builder" || strings.HasPrefix(r.URL.Path, "/api/v1/builder/") {
		a.serveBuilder(w, r)
		return
	}
	if r.URL.Path == "/api/v1/subscription-sets" || strings.HasPrefix(r.URL.Path, "/api/v1/subscription-sets/") {
		a.serveSubscriptionSets(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/subscriptions/") {
		a.serveSubscriptions(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api" {
		a.static(w, r)
		return
	}
	if r.URL.Path == "/api/v1/sources" || strings.HasPrefix(r.URL.Path, "/api/v1/sources/") {
		a.serveSources(w, r)
		return
	}
	if r.URL.Path == "/api/v1/nodes" || strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") || strings.HasPrefix(r.URL.Path, "/api/v1/node/") {
		a.serveNodes(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/access/") {
		a.serveAccess(w, r)
		return
	}
	known := map[string]string{
		"/api/v1/setup/status": "GET", "/api/v1/setup": "POST",
		"/api/v1/auth/login": "POST", "/api/v1/auth/session": "GET",
		"/api/v1/auth/logout": "POST", "/api/v1/auth/revoke-sessions": "POST",
		"/api/v1/admins": "GET, POST", "/api/v1/overview": "GET",
		"/api/v1/operations": "GET, POST", "/api/v1/audit": "GET",
	}
	allowed, ok := known[r.URL.Path]
	adminID := ""
	if !ok && strings.HasPrefix(r.URL.Path, "/api/v1/admins/") {
		adminID = strings.TrimPrefix(r.URL.Path, "/api/v1/admins/")
		ok, allowed = identity.ValidID(adminID), "PATCH"
	}
	if !ok {
		writeError(w, 404, "not_found")
		return
	}
	if !method(w, r, strings.Split(allowed, ", ")...) {
		return
	}
	unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead
	if unsafe && (len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != a.config.Origin) {
		writeError(w, 403, "origin_failed")
		return
	}
	switch r.URL.Path {
	case "/api/v1/setup/status":
		required, err := a.identity.SetupRequired(ctx)
		if fail(w, err) {
			return
		}
		writeJSON(w, 200, map[string]bool{"setup_required": required})
		return
	case "/api/v1/setup":
		var body struct {
			Token    string `json:"token"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decode(w, r, &body) {
			return
		}
		user, err := a.identity.Bootstrap(ctx, body.Token, body.Username, body.Password, directIP(r))
		if fail(w, err) {
			return
		}
		writeJSON(w, 201, map[string]any{"user": user})
		return
	case "/api/v1/auth/login":
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decode(w, r, &body) {
			return
		}
		session, err := a.identity.Login(ctx, body.Username, body.Password, directIP(r))
		if fail(w, err) {
			return
		}
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: session.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds())})
		writeJSON(w, 200, session)
		return
	}
	token := ""
	if cookie, err := r.Cookie(CookieName); err == nil {
		token = cookie.Value
	}
	session, err := a.identity.Authenticate(ctx, token)
	if fail(w, err) {
		return
	}
	if unsafe {
		if len(r.Header.Values("X-CSRF-Token")) != 1 {
			fail(w, identity.ErrCSRF)
			return
		}
		if fail(w, identity.CheckCSRF(session, r.Header.Get("X-CSRF-Token"))) {
			return
		}
	}
	switch r.URL.Path {
	case "/api/v1/auth/session":
		writeJSON(w, 200, session)
	case "/api/v1/auth/logout", "/api/v1/auth/revoke-sessions":
		var body struct{}
		if !decode(w, r, &body) || fail(w, a.identity.Logout(ctx, token, r.URL.Path == "/api/v1/auth/revoke-sessions")) {
			return
		}
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: time.Unix(1, 0), MaxAge: -1})
		writeJSON(w, 200, struct{}{})
	case "/api/v1/admins":
		if !role(w, session, identity.Owner) {
			return
		}
		if r.Method == http.MethodGet {
			items, err := a.identity.ListAdmins(ctx)
			if !fail(w, err) {
				writeJSON(w, 200, map[string]any{"items": items})
			}
			return
		}
		var body struct {
			Username string        `json:"username"`
			Password string        `json:"password"`
			Role     identity.Role `json:"role"`
		}
		if !decode(w, r, &body) {
			return
		}
		user, err := a.identity.CreateAdmin(ctx, token, body.Username, body.Password, body.Role)
		if !fail(w, err) {
			w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(user.Revision, 10)))
			writeJSON(w, 201, user)
		}
	case "/api/v1/overview":
		var count int64
		err := a.pool.QueryRow(ctx, "SELECT count(*) FROM admins").Scan(&count)
		if err != nil {
			fail(w, err)
			return
		}
		counts, err := a.jobs.Counts(ctx)
		if err != nil {
			fail(w, identity.ErrUnavailable)
			return
		}
		writeJSON(w, 200, map[string]any{"service_status": "ok", "database_status": "ok", "vpn_status": "per_node", "build_version": a.config.BuildVersion,
			"counts": map[string]int64{"admins": count, "jobs_pending": counts["pending"] + counts["running"], "jobs_failed": counts["failed"]}})
	case "/api/v1/operations":
		if r.Method == http.MethodPost {
			if !role(w, session, identity.Owner, identity.InfrastructureOperator) {
				return
			}
			var body struct {
				Kind string `json:"kind"`
			}
			if !decode(w, r, &body) {
				return
			}
			if len(r.Header.Values("Idempotency-Key")) != 1 {
				fail(w, identity.ErrInvalid)
				return
			}
			var job jobs.Job
			var created bool
			err := a.identity.WithAuthorizedSession(ctx, token, []identity.Role{identity.Owner, identity.InfrastructureOperator}, func(tx pgx.Tx, current identity.Session) error {
				var err error
				job, created, err = a.jobs.EnqueueTx(ctx, tx, current.User.ID, body.Kind, r.Header.Get("Idempotency-Key"), json.RawMessage(`{}`))
				return err
			})
			if !fail(w, err) {
				if !created {
					w.Header().Set("Idempotent-Replayed", "true")
				}
				writeJSON(w, 202, job)
			}
			return
		}
		limit, cursor, ok := pagination(w, r)
		if !ok {
			return
		}
		items, err := a.jobs.List(ctx, limit, cursor)
		if !fail(w, err) {
			next := ""
			if len(items) == limit {
				next = items[len(items)-1].ID
			}
			writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
		}
	case "/api/v1/audit":
		if !role(w, session, identity.Owner, identity.Auditor) {
			return
		}
		limit, cursor, ok := pagination(w, r)
		if !ok {
			return
		}
		items, err := audit.New(a.pool).List(ctx, limit, cursor)
		if err != nil {
			fail(w, err)
			return
		}
		next := ""
		if len(items) == limit {
			next = items[len(items)-1].ID
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
	default:
		if !role(w, session, identity.Owner) {
			return
		}
		var body struct {
			Role     *identity.Role `json:"role"`
			Disabled *bool          `json:"disabled"`
		}
		if !decode(w, r, &body) {
			return
		}
		match := r.Header.Get("If-Match")
		n, err := strconv.Unquote(match)
		if err != nil || len(r.Header.Values("If-Match")) != 1 {
			fail(w, identity.ErrInvalid)
			return
		}
		revision, err := strconv.ParseInt(n, 10, 64)
		if err != nil || strconv.FormatInt(revision, 10) != n {
			fail(w, identity.ErrInvalid)
			return
		}
		user, err := a.identity.UpdateAdmin(ctx, token, adminID, revision, body.Role, body.Disabled)
		if !fail(w, err) {
			w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(user.Revision, 10)))
			writeJSON(w, 200, user)
		}
	}
}

func directIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}

func method(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, 405, "method_not_allowed")
	return false
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	return decodeLimit(w, r, value, MaxBodyBytes)
}
func decodeLimit(w http.ResponseWriter, r *http.Request, value any, limit int64) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 415, "invalid_request")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	raw, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(raw) || !importer.ValidJSONUnicode(raw) {
		writeError(w, 400, "invalid_request")
		return false
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		writeError(w, 400, "invalid_request")
		return false
	}
	typ := reflect.TypeOf(value).Elem()
	fields := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		fields[typ.Field(i).Tag.Get("json")] = typ.Field(i).Type
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || fields[name] == nil {
			writeError(w, 400, "invalid_request")
			return false
		}
		seen[name] = true
		var part json.RawMessage
		if d.Decode(&part) != nil || string(part) == "null" {
			writeError(w, 400, "invalid_request")
			return false
		}
	}
	if _, err := d.Token(); err != nil {
		writeError(w, 400, "invalid_request")
		return false
	}
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, 400, "invalid_request")
		return false
	}
	for name, typ := range fields {
		if typ.Kind() != reflect.Pointer && !seen[name] {
			writeError(w, 400, "invalid_request")
			return false
		}
	}
	if json.Unmarshal(raw, value) != nil {
		writeError(w, 400, "invalid_request")
		return false
	}
	return true
}

func role(w http.ResponseWriter, s identity.Session, allowed ...identity.Role) bool {
	for _, role := range allowed {
		if role == s.User.Role {
			return true
		}
	}
	writeError(w, 403, "forbidden")
	return false
}

func pagination(w http.ResponseWriter, r *http.Request) (int, string, bool) {
	q := r.URL.Query()
	for key, values := range q {
		if (key != "cursor" && key != "limit") || len(values) != 1 {
			fail(w, identity.ErrInvalid)
			return 0, "", false
		}
	}
	limit := 50
	if q.Has("limit") {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 1 || n > 100 {
			fail(w, identity.ErrInvalid)
			return 0, "", false
		}
		limit = n
	}
	cursor := q.Get("cursor")
	if cursor != "" && !identity.ValidID(cursor) {
		fail(w, identity.ErrInvalid)
		return 0, "", false
	}
	return limit, cursor, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "request_id": w.Header().Get("X-Request-ID")}})
}

func fail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	status, code := 503, "unavailable"
	switch {
	case errors.Is(err, identity.ErrInvalid), errors.Is(err, jobs.ErrInvalid), errors.Is(err, audit.ErrInvalid):
		status, code = 400, "invalid_request"
	case errors.Is(err, identity.ErrCredentials):
		status, code = 401, "invalid_credentials"
	case errors.Is(err, identity.ErrUnauthorized):
		status, code = 401, "unauthenticated"
	case errors.Is(err, identity.ErrForbidden):
		status, code = 403, "forbidden"
	case errors.Is(err, identity.ErrCSRF):
		status, code = 403, "csrf_failed"
	case errors.Is(err, identity.ErrRateLimited):
		status, code = 429, "rate_limited"
		w.Header().Set("Retry-After", "900")
	case errors.Is(err, identity.ErrSetup):
		status, code = 409, "setup_unavailable"
	case errors.Is(err, identity.ErrConflict), errors.Is(err, jobs.ErrConflict):
		status, code = 409, "conflict"
	case errors.Is(err, identity.ErrRevision):
		status, code = 412, "revision_conflict"
	case errors.Is(err, identity.ErrLastOwner):
		status, code = 409, "last_owner"
	case errors.Is(err, identity.ErrNotFound), errors.Is(err, jobs.ErrNotFound), errors.Is(err, audit.ErrNotFound):
		status, code = 404, "not_found"
	}
	writeError(w, status, code)
	return true
}

func (a *api) static(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	switch r.URL.Path {
	case "/", "/login", "/setup", "/admins", "/operations", "/audit", "/users", "/nodes", "/subscriptions", "/legacy-subscriptions", "/antifraud", "/sources", "/constructor", "/diagnostics":
		name = "index.html"
	}
	if strings.HasPrefix(r.URL.Path, "/users/") && identity.ValidID(strings.TrimPrefix(r.URL.Path, "/users/")) {
		name = "index.html"
	}
	if a.config.Static == nil || !fs.ValidPath(name) || strings.HasPrefix(name, ".") || strings.Contains(name, "/.") {
		writeError(w, 404, "not_found")
		return
	}
	data, err := fs.ReadFile(a.config.Static, name)
	if err != nil {
		writeError(w, 404, "not_found")
		return
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}
