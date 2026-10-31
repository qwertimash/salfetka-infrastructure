// Package antifraudnode implements the authenticated byte-budget protocol.
// It does not configure a VPN, invent account mappings, or claim coverage until
// the embedding runtime explicitly calls Sync after installing Wait as its gate.
package antifraudnode

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"salfetka/panel/internal/antifraud"
	"salfetka/panel/internal/appconfig"
)

var ErrUnavailable = errors.New("antifraud_node_unavailable")
var ErrInvalid = errors.New("antifraud_node_invalid")
var ErrPermitExpired = errors.New("antifraud_permit_expired")
var ErrStale = errors.New("antifraud_node_stale")
var ErrQueue = errors.New("antifraud_queue_full")
var nonce = regexp.MustCompile(`^[0-9a-f]{48}$`)

const maxBody = 2 * 1024 * 1024
const validityNS = int64(200 * time.Millisecond)

type policy struct {
	Account  string `json:"account_id"`
	Revision int64  `json:"revision"`
	Limited  bool   `json:"limited"`
	UntilMS  *int64 `json:"until_ms"`
	Rate     *int64 `json:"aggregate_bps"`
	Scope    string `json:"budget_scope"`
}
type permit struct {
	Limited   *bool  `json:"limited"`
	Status    string `json:"status"`
	Revision  int64  `json:"revision"`
	Sequence  int64  `json:"sequence"`
	Bytes     int    `json:"bytes"`
	SendNS    int64  `json:"send_at_ns"`
	ExpiresNS int64  `json:"expires_ns"`
	ServerNS  int64  `json:"server_ns"`
	RetryNS   int64  `json:"retry_ns"`
}
type account struct {
	queue    chan struct{}
	waiting  atomic.Int64
	sequence int64
	policy   policy
	known    bool
}
type Client struct {
	origin, session string
	http            *http.Client
	bindings        map[string]string
	accounts        map[string]*account
	mu              sync.RWMutex
	syncMu          sync.Mutex
	receiptSeq      int64
}

// A controller outage pauses limited users until it recovers. Normal accounts
// keep the last confirmed clear state. There is no fail-open bypass switch.
// TLS verifies both the controller certificate and a dedicated client identity.
func New(origin string, config *tls.Config, session string, bindings map[string]string) (*Client, error) {
	if !appconfig.HTTPSOrigin(origin) || config == nil || config.InsecureSkipVerify || len(config.Certificates) != 1 || !nonce.MatchString(session) || len(bindings) == 0 || len(bindings) > 10000 {
		return nil, ErrInvalid
	}
	tlsConfig := config.Clone()
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig
	transport.MaxConnsPerHost = 32
	c := &Client{origin: origin, session: session, http: &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, bindings: map[string]string{}, accounts: map[string]*account{}}
	for id, a := range bindings {
		if !antifraud.ValidID(id) || !antifraud.ValidID(a) {
			return nil, ErrInvalid
		}
		c.bindings[id] = a
		c.accounts[a] = &account{queue: make(chan struct{}, 1)}
	}
	return c, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) request(ctx context.Context, method, path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return ErrInvalid
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(data))
	if err != nil {
		return ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode >= 500 {
		return ErrUnavailable
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil || len(data) > maxBody {
		return ErrUnavailable
	}
	if res.StatusCode != 200 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &failure)
		if res.StatusCode == 409 && (failure.Error == "control_clock_regressed" || failure.Error == "budget_clock_regressed") {
			return ErrUnavailable
		}
		if res.StatusCode == 409 && (failure.Error == "permit_expired" || failure.Error == "stale_budget_request") {
			return ErrPermitExpired
		}
		return ErrStale
	}
	if json.Unmarshal(data, out) != nil {
		return ErrInvalid
	}
	return nil
}

// OpenSession requires a durable caller-generated proposed nonce. Persist it
// before calling and retry the exact previous/proposed pair after a lost reply.
func (c *Client) OpenSession(ctx context.Context, previous string) error {
	body := map[string]any{"proposed": c.session}
	if previous != "" {
		if !nonce.MatchString(previous) {
			return ErrInvalid
		}
		body["previous"] = previous
	}
	var result struct {
		Session string `json:"session"`
	}
	if err := c.request(ctx, "POST", "/agent/session", body, &result); err != nil {
		return err
	}
	if result.Session != c.session {
		return ErrStale
	}
	return nil
}

// Sync is called only after every supplied identity is attached to the data
// path. Missing controller identities fail the whole snapshot, not to clear.
func (c *Client) Sync(ctx context.Context) error {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	var result struct {
		Commands []policy `json:"commands"`
	}
	if err := c.request(ctx, "GET", "/agent/commands", nil, &result); err != nil {
		return err
	}
	found := map[string]policy{}
	for _, p := range result.Commands {
		if _, exists := found[p.Account]; exists || !antifraud.ValidID(p.Account) || p.Revision < 0 || p.Scope != "account_all_nodes_upload_plus_download" {
			return ErrInvalid
		}
		if !p.Limited && (p.UntilMS != nil || p.Rate != nil) {
			return ErrInvalid
		}
		if p.Limited && (p.UntilMS == nil || p.Rate == nil || *p.Rate != 1000000 || p.Revision == 0) {
			return ErrInvalid
		}
		found[p.Account] = p
	}
	c.mu.Lock()
	for id, a := range c.accounts {
		p, exists := found[id]
		if !exists || a.known && (p.Revision < a.policy.Revision || p.Revision == a.policy.Revision && p.Limited != a.policy.Limited) {
			c.mu.Unlock()
			return ErrStale
		}
	}
	for id, a := range c.accounts {
		a.policy = found[id]
		a.known = true
	}
	c.mu.Unlock()
	// A node cannot acknowledge accounts for which this adapter has no bindings.
	for id := range c.accounts {
		p := found[id]
		if p.Revision == 0 {
			continue
		}
		c.receiptSeq++
		var response map[string]any
		if err := c.request(ctx, "POST", "/agent/receipt", map[string]any{"account_id": id, "revision": p.Revision, "limited": p.Limited, "applied": true, "sequence": c.receiptSeq, "session": c.session}, &response); err != nil {
			return err
		}
	}
	return nil
}
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait is shared across all connections and both directions of an account in
// this process. The controller additionally serializes the account across nodes.
func (c *Client) Wait(ctx context.Context, identity, direction string, size int) error {
	id, ok := c.bindings[identity]
	if !ok || (direction != "upload" && direction != "download") || size < 0 || size > 65535 {
		return ErrInvalid
	}
	if size == 0 {
		return nil
	}
	a := c.accounts[id]
	c.mu.RLock()
	known, limited := a.known, a.policy.Limited
	c.mu.RUnlock()
	if !known {
		return ErrStale
	}
	if !limited {
		return nil
	}
	if a.waiting.Add(1) > 128 {
		a.waiting.Add(-1)
		return ErrQueue
	}
	defer a.waiting.Add(-1)
	select {
	case a.queue <- struct{}{}:
		defer func() { <-a.queue }()
	case <-ctx.Done():
		return ctx.Err()
	}
	a.sequence++
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.RLock()
		limited = a.policy.Limited
		c.mu.RUnlock()
		if !limited {
			return nil
		}
		started := time.Now()
		var p permit
		err := c.request(ctx, "POST", "/agent/reserve", map[string]any{"account_id": id, "session": c.session, "sequence": a.sequence, "bytes": size, "direction": direction}, &p)
		received := time.Now()
		if err != nil {
			if errors.Is(err, ErrPermitExpired) {
				a.sequence++
				continue
			}
			// Stale-session/auth errors never bypass even under allow: this process no
			// longer owns the account adapter. A transport outage pauses this account.
			if !errors.Is(err, ErrUnavailable) {
				return err
			}
			if err = wait(ctx, time.Second); err != nil {
				return err
			}
			continue
		}
		if p.Limited == nil {
			return ErrInvalid
		}
		if !*p.Limited {
			return nil
		}
		if p.Status == "wait" {
			if p.RetryNS <= 0 || p.RetryNS > int64(24*time.Hour) {
				return ErrInvalid
			}
			if err = wait(ctx, min(time.Duration(p.RetryNS), time.Second)); err != nil {
				return err
			}
			continue
		}
		if p.SendNS-p.ServerNS > int64(time.Second) || p.ExpiresNS-p.ServerNS <= 0 || p.Status != "permit" || p.Sequence != a.sequence || p.Bytes != size || p.Revision <= 0 || p.ServerNS <= 0 || p.ExpiresNS <= p.SendNS || p.ExpiresNS-p.SendNS > validityNS {
			return ErrInvalid
		}
		earliest := received.Add(time.Duration(max(int64(0), p.SendNS-p.ServerNS)))
		expires := started.Add(time.Duration(p.ExpiresNS - p.ServerNS))
		if !earliest.Before(expires) {
			a.sequence++
			continue
		}
		if err = wait(ctx, time.Until(earliest)); err != nil {
			return err
		}
		if !time.Now().Before(expires) {
			a.sequence++
			continue
		}
		return nil
	}
}

// A missing boolean must never decode as permission to pass traffic.
func (p *policy) UnmarshalJSON(data []byte) error {
	type raw policy
	var out raw
	var flags struct {
		Limited  *bool  `json:"limited"`
		Revision *int64 `json:"revision"`
	}
	if json.Unmarshal(data, &out) != nil || json.Unmarshal(data, &flags) != nil || flags.Limited == nil || flags.Revision == nil {
		return ErrInvalid
	}
	*p = policy(out)
	return nil
}
