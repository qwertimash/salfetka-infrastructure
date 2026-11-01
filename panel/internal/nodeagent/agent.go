package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"salfetka/panel/internal/nodesite"
	"salfetka/panel/internal/nodewire"
	"strings"
	"sync"
	"time"
)

type Config struct {
	SiteDir                                        string
	ManagedConnections                             bool
	StateDir, PanelURL, CAFile, TokenFile, Version string
	SignerPublicFile                               string
	ExpectedNodeID                                 string
	HeartbeatInterval                              time.Duration
}
type Agent struct {
	mu                     sync.Mutex
	cfg                    Config
	ca                     []byte
	dir, lock              int
	state                  localState
	client                 *http.Client
	bypassSlots            chan struct{}
	bootID                 string
	sequence               int64
	pending                *nodewire.HeartbeatRequest
	closed                 bool
	signer                 ed25519.PublicKey
	now                    func() time.Time
	monotonic              func() time.Time
	anchorWall, anchorMono time.Time
	persist                func(int, localState) error
	storagePoisoned        bool
}

func Open(cfg Config) (*Agent, error) {
	if cfg.ExpectedNodeID != "" && !uuidPattern.MatchString(cfg.ExpectedNodeID) {
		return nil, fault("node_expected_identity_invalid")
	}
	u, err := url.Parse(cfg.PanelURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fault("node_https_origin_required")
	}
	if cfg.Version == "" {
		cfg.Version = "0.3.0-b3.3"
	}
	if len(cfg.Version) > 64 || strings.IndexFunc(cfg.Version, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return nil, fault("node_version_invalid")
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 15 * time.Second
	}
	if cfg.HeartbeatInterval < time.Second || cfg.HeartbeatInterval > 5*time.Minute {
		return nil, fault("node_interval_invalid")
	}
	ca, err := readExternal(cfg.CAFile, false)
	if err != nil {
		return nil, err
	}
	if _, err = serverRoots(ca); err != nil {
		return nil, err
	}
	dir, lock, err := openStateDir(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, ca: ca, dir: dir, lock: lock, sequence: 1, now: time.Now, monotonic: time.Now, persist: writeState}
	a.anchorWall, a.anchorMono = time.Now().UTC(), time.Now()
	fail := func(err error) (*Agent, error) { a.Close(); return nil, err }
	raw, err := readState(dir)
	if err != nil {
		return fail(err)
	}
	if raw != nil {
		if err = decodeJSON(raw, &a.state); err != nil {
			return fail(err)
		}
		if _, err = validateState(a.state, cfg, ca); err != nil {
			return fail(err)
		}
	}
	if cfg.ExpectedNodeID != "" && a.state.NodeID != cfg.ExpectedNodeID {
		return fail(fault("node_expected_identity_mismatch"))
	}
	if err = a.loadControl(); err != nil {
		return fail(err)
	}
	a.bootID, err = newID()
	if err != nil {
		return fail(err)
	}
	if err = a.makeClient(); err != nil {
		return fail(err)
	}
	return a, nil
}
func (a *Agent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	if a.client != nil {
		a.client.CloseIdleConnections()
	}
	unix.Close(a.lock)
	unix.Close(a.dir)
}
func (a *Agent) makeClient() error {
	roots, err := serverRoots(a.ca)
	if err != nil {
		return err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if a.state.Enrollment != nil {
		pair, err := tls.X509KeyPair([]byte(a.state.Enrollment.CertificatePEM), []byte(a.state.PrivateKeyPEM))
		if err != nil {
			return fault("node_client_certificate_invalid")
		}
		config.Certificates = []tls.Certificate{pair}
	}
	if a.client != nil {
		a.client.CloseIdleConnections()
	}
	a.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: config, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return nil
}
func (a *Agent) post(ctx context.Context, path string, body, target any) error {
	return a.request(ctx, http.MethodPost, path, body, target)
}
func (a *Agent) request(ctx context.Context, method, path string, body, target any) error {
	return a.requestUsing(ctx, method, path, body, target, a.client)
}

func (a *Agent) requestUsing(ctx context.Context, method, path string, body, target any, client *http.Client) error {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
	}
	if err != nil {
		return fault("node_request_invalid")
	}
	request, err := http.NewRequestWithContext(ctx, method, a.cfg.PanelURL+path, bytes.NewReader(encoded))
	if err != nil {
		return fault("node_request_invalid")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return fault("node_tls_verification_failed")
		}
		return fault("node_connection_failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		switch response.StatusCode {
		case 401, 403:
			return fault("node_authorization_rejected")
		case 409:
			return fault("node_request_conflict")
		case 429:
			return fault("node_rate_limited")
		case 301, 302, 303, 307, 308:
			return fault("node_redirect_rejected")
		default:
			return fault("node_http_rejected")
		}
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return fault("node_response_invalid")
	}
	maximum := maxPrivateBytes
	if path == nodewire.ConnectionsDesiredPath {
		maximum = 8 * 1024 * 1024
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum+1)))
	if err != nil || len(raw) > maximum {
		return fault("node_response_invalid")
	}
	if err = decodeJSON(raw, target); err != nil {
		return fault("node_response_invalid")
	}
	return nil
}
func (a *Agent) Enroll(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.storagePoisoned {
		return fault("node_control_storage_failed")
	}
	if a.closed {
		return fault("node_agent_closed")
	}
	if a.state.Enrollment != nil {
		return nil
	}
	raw, err := readExternal(a.cfg.TokenFile, true)
	if err != nil {
		return err
	}
	var token enrollmentToken
	if decodeJSON(raw, &token) != nil {
		return fault("node_enrollment_file_invalid")
	}
	if a.state.SchemaVersion == 0 {
		next, err := newState(a.cfg, a.ca, token)
		if err != nil {
			return err
		}
		if err = a.persist(a.dir, next); err != nil {
			a.storagePoisoned = true
			return err
		}
		a.state = next
	} else if token.NodeID != a.state.NodeID || digest([]byte(token.Token)) != a.state.TokenHash {
		return fault("node_enrollment_identity_changed")
	}
	request := nodewire.EnrollmentRequest{SchemaVersion: nodewire.SchemaVersion, NodeID: a.state.NodeID, Token: token.Token, RequestID: a.state.RequestID, CSRPEM: a.state.CSRPEM}
	var response nodewire.EnrollmentResponse
	if err = a.post(ctx, nodewire.EnrollmentPath, request, &response); err != nil {
		return err
	}
	key, err := parseKey(a.state.PrivateKeyPEM)
	if err != nil {
		return err
	}
	if _, err = verifyEnrollment(response, a.state.NodeID, key); err != nil {
		return err
	}
	next := a.state
	next.Enrollment = &response
	if err = a.persist(a.dir, next); err != nil {
		a.storagePoisoned = true
		return err
	}
	a.state = next
	return a.makeClient()
}
func certificate(raw string) (*x509.Certificate, error) {
	block, err := onlyPEM(raw, "CERTIFICATE")
	if err != nil {
		return nil, fault("node_client_certificate_invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fault("node_client_certificate_invalid")
	}
	return cert, nil
}
func verifyEnrollment(response nodewire.EnrollmentResponse, nodeID string, key ed25519.PrivateKey) (*x509.Certificate, error) {
	if response.SchemaVersion != nodewire.SchemaVersion || response.NodeID != nodeID {
		return nil, fault("node_enrollment_response_mismatch")
	}
	cert, err := certificate(response.CertificatePEM)
	if err != nil {
		return nil, err
	}
	authority, err := certificate(response.AuthorityPEM)
	if err != nil || !authority.IsCA || authority.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fault("node_authority_invalid")
	}
	if !cert.NotAfter.After(time.Now()) {
		return nil, fault("node_certificate_expired")
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) || cert.Subject.CommonName != nodeID || len(cert.URIs) != 1 || cert.URIs[0].String() != nodewire.IdentityURIPrefix+nodeID || response.Serial != cert.SerialNumber.Text(16) || !response.ExpiresAt.Equal(cert.NotAfter) {
		return nil, fault("node_enrollment_response_mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fault("node_client_certificate_invalid")
	}
	return cert, nil
}
func (a *Agent) Heartbeat(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.storagePoisoned {
		return fault("node_control_storage_failed")
	}
	if a.closed {
		return fault("node_agent_closed")
	}
	if a.state.Enrollment == nil {
		return fault("node_not_enrolled")
	}
	key, err := parseKey(a.state.PrivateKeyPEM)
	if err != nil {
		return err
	}
	if _, err = verifyEnrollment(*a.state.Enrollment, a.state.NodeID, key); err != nil {
		return err
	}
	if a.sequence > 9007199254740991 {
		return fault("node_sequence_exhausted")
	}
	if a.pending == nil {
		a.pending = &nodewire.HeartbeatRequest{SchemaVersion: nodewire.SchemaVersion, NodeID: a.state.NodeID, BootID: a.bootID, Sequence: a.sequence, Version: a.cfg.Version, Platform: runtime.GOOS, Arch: runtime.GOARCH, Capabilities: []string{"enrollment", "heartbeat", "certificate_renewal"}}
		if a.cfg.SiteDir != "" {
			if cfg, err := nodesite.LoadConfig(a.cfg.SiteDir); err == nil {
				a.pending.Site = &nodewire.SiteStatus{Domain: cfg.Domain, State: "unavailable"}
				if cert, err := nodesite.Load(a.cfg.SiteDir, cfg.Domain, a.now()); err == nil && nodesite.Probe(cfg.Domain, cert) == nil {
					a.pending.Site.State = "ready"
					a.pending.Site.CertificatePEM = cert.PEM
					a.pending.Site.ExpiresAt = cert.ExpiresAt
				}
			}
		}
		if a.cfg.ManagedConnections {
			a.pending.Capabilities = append(a.pending.Capabilities, "managed_connections_v1")
		}
	}
	var response nodewire.HeartbeatResponse
	if err = a.post(ctx, nodewire.HeartbeatPath, a.pending, &response); err != nil {
		return err
	}
	if response.SchemaVersion != nodewire.SchemaVersion || response.NodeID != a.state.NodeID || response.Sequence != a.pending.Sequence || response.Status != "recorded" || response.EngineState != "not_configured" || response.ReceivedAt.IsZero() {
		return fault("node_heartbeat_response_mismatch")
	}
	next := a.state
	next.LastHeartbeat = &response
	next = a.withWall(next)
	if err = a.persist(a.dir, next); err != nil {
		if next.Control != nil {
			a.storagePoisoned = true
			return fault("node_control_storage_failed")
		}
		return err
	}
	a.state = next
	a.pending = nil
	a.sequence++
	return nil
}
func retryDelay(failures int) time.Duration {
	if failures > 5 {
		return 30 * time.Second
	}
	if failures < 1 {
		return time.Second
	}
	return time.Duration(1<<uint(failures-1)) * time.Second
}

// Run reports fixed safe codes. Revocation/expiry/conflict stop; transient errors
// retry the exact pending heartbeat. No engine or configuration is executed.
func (a *Agent) Run(ctx context.Context, report func(string)) error {
	failures := 0
	for {
		if renewalErr := a.Renew(ctx); renewalErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			if report != nil {
				report(renewalErr.Error())
			}
			switch renewalErr.Error() {
			case "node_authorization_rejected", "node_certificate_expired", "node_not_enrolled", "node_agent_closed", "node_control_storage_failed", "node_clock_untrusted", "node_renewal_response_invalid":
				return renewalErr
			}
		}
		err := a.Heartbeat(ctx)
		if ctx.Err() != nil {
			return nil
		}
		delay := a.EffectiveInterval()
		if err != nil {
			if report != nil {
				report(err.Error())
			}
			switch err.Error() {
			case "node_authorization_rejected", "node_certificate_expired", "node_request_conflict", "node_not_enrolled", "node_agent_closed", "node_control_storage_failed":
				return err
			}
			failures++
			delay = retryDelay(failures)
		} else {
			failures = 0
			if report != nil {
				report("node_heartbeat_recorded")
			}
			if controlErr := a.SyncControl(ctx); controlErr != nil {
				if report != nil {
					report(controlErr.Error())
				}
				if controlErr.Error() == "node_control_storage_failed" {
					return controlErr
				}
			} else if a.signer != nil && report != nil {
				report("node_control_synchronized")
			}
			delay = a.EffectiveInterval()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
