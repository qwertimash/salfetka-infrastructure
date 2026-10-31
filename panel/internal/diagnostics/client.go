// Package diagnostics reads the independent collector. No device credentials,
// arbitrary upstream URL, admin mutation or raw upstream errors cross this API.
package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"salfetka/panel/internal/appconfig"
	"time"
)

var ErrUnavailable = errors.New("diagnostics_unavailable")
var ErrInvalid = errors.New("diagnostics_invalid_query")
var ErrNotFound = errors.New("diagnostics_not_found")
var uuid = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
var cursor = regexp.MustCompile(`^[0-9]{1,16}\|[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
var keyPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

const MaxResponse = 4 * 1024 * 1024

type Reader interface {
	Read(context.Context, string, string) (json.RawMessage, error)
}
type Client struct {
	origin, key string
	http        *http.Client
	slots       chan struct{}
}

func New(origin, key string) (*Client, error) {
	if !appconfig.HTTPSOrigin(origin) || !keyPattern.MatchString(key) {
		return nil, errors.New("diagnostics_configuration_invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // fixed independent service; do not inherit proxy credentials
	transport.MaxConnsPerHost = 4
	return &Client{origin: origin, key: key, slots: make(chan struct{}, 4), http: &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func ValidQuery(tester, before string) bool {
	return (tester == "" && before == "") || uuid.MatchString(tester) && (before == "" || cursor.MatchString(before))
}
func (c *Client) Read(ctx context.Context, tester, before string) (json.RawMessage, error) {
	if !ValidQuery(tester, before) {
		return nil, ErrInvalid
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return nil, ErrUnavailable
	}
	target := c.origin + "/panel/v1/testers"
	if tester != "" {
		target += "/" + tester + "?limit=200"
		if before != "" {
			target += "&before=" + url.QueryEscape(before)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if res.StatusCode != 200 {
		return nil, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxResponse+1))
	if err != nil || len(body) > MaxResponse || !json.Valid(body) {
		return nil, ErrUnavailable
	}
	// Require an object of the expected view, not an HTML/login or scalar response.
	var shape map[string]json.RawMessage
	if json.Unmarshal(body, &shape) != nil || shape == nil {
		return nil, ErrUnavailable
	}
	if tester == "" {
		if _, ok := shape["testers"]; !ok {
			return nil, ErrUnavailable
		}
	} else {
		if _, ok := shape["events"]; !ok {
			return nil, ErrUnavailable
		}
	}
	return body, nil
}
