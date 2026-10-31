// Package antifraud bridges a fixed controller origin. It never edits VPN
// accounts and never accepts an upstream URL or recipient from a browser.
package antifraud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"salfetka/panel/internal/appconfig"
)

var ErrUnavailable = errors.New("antifraud_unavailable")
var ErrConflict = errors.New("antifraud_conflict")
var ErrInvalid = errors.New("antifraud_invalid")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,96}$`)

const maxResponse = 2 * 1024 * 1024

func ValidID(id string) bool { return idPattern.MatchString(id) }

type Policy struct {
	Revision       int64    `json:"revision"`
	IncidentID     *int64   `json:"incident_id"`
	Limited        bool     `json:"limited"`
	UntilMS        *int64   `json:"until_ms"`
	State          string   `json:"state"`
	RequiredNodes  []string `json:"required_nodes"`
	ConfirmedNodes []string `json:"confirmed_nodes"`
	FailedNodes    []string `json:"failed_nodes"`
}
type Incident struct {
	ID             int64   `json:"id"`
	AccountID      string  `json:"account_id"`
	TriggeredAt    int64   `json:"triggered_at"`
	UntilMS        int64   `json:"until_ms"`
	ThresholdBytes int64   `json:"threshold_bytes"`
	EvidenceBytes  int64   `json:"evidence_bytes"`
	EndedAt        *int64  `json:"ended_at"`
	EndedBy        *string `json:"ended_by"`
	EndReason      *string `json:"end_reason"`
}
type Account struct {
	ID                 string    `json:"account_id"`
	Plan               string    `json:"plan"`
	CandidateBytes     int64     `json:"candidate_bytes"`
	WindowStartMS      int64     `json:"window_start_ms"`
	AsOfMS             int64     `json:"as_of_ms"`
	DownloadLowerBytes int64     `json:"download_lower_bytes"`
	DownloadUpperBytes *int64    `json:"download_upper_bytes"`
	MeasurementStatus  string    `json:"measurement_status"`
	CoverageComplete   bool      `json:"coverage_complete"`
	QualityReasons     []string  `json:"quality_reasons"`
	MeterCount         int       `json:"meter_count"`
	Policy             Policy    `json:"policy"`
	Incident           *Incident `json:"incident"`
	NotificationState  string    `json:"notification_state"`
}
type Page struct {
	Items         []Account `json:"items"`
	NextCursor    string    `json:"next_cursor"`
	GeneratedAtMS int64     `json:"generated_at_ms"`
	CoverageScope string    `json:"coverage_scope"`
	AggregateBPS  int64     `json:"aggregate_bps"`
}
type Service interface {
	Read(context.Context, string) (Page, error)
	Release(context.Context, string, int64, string) (bool, error)
}
type Client struct {
	origin, key string
	http        *http.Client
	slots       chan struct{}
}

func New(origin, key string) (*Client, error) {
	if !appconfig.HTTPSOrigin(origin) || len(key) < 48 || len(key) > 256 || strings.ContainsAny(key, "\r\n\t ") {
		return nil, ErrInvalid
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 4
	return &Client{origin: origin, key: key, slots: make(chan struct{}, 4), http: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) request(ctx context.Context, method, path string, body any, result any) error {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return ErrUnavailable
	}
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return ErrInvalid
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(payload))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode == 409 {
		return ErrConflict
	}
	if res.StatusCode != 200 {
		return ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return ErrUnavailable
	}
	if err = json.Unmarshal(data, result); err != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Client) Read(ctx context.Context, after string) (Page, error) {
	var page Page
	if after != "" && !ValidID(after) {
		return page, ErrInvalid
	}
	err := c.request(ctx, "GET", "/admin/accounts?after="+url.QueryEscape(after), nil, &page)
	if err != nil {
		return Page{}, err
	}
	// Typed projection drops unknown fields, including any future secret field.
	if page.Items == nil || len(page.Items) > 100 || page.GeneratedAtMS <= 0 || page.CoverageScope != "declared_client_ingress_meters_only" || page.AggregateBPS != 1000000 || page.NextCursor != "" && !ValidID(page.NextCursor) {
		return Page{}, ErrUnavailable
	}
	previous := after
	for _, a := range page.Items {
		if !ValidID(a.ID) || a.ID <= previous || a.MeterCount < 1 || a.DownloadLowerBytes < 0 || a.AsOfMS != page.GeneratedAtMS || a.CandidateBytes != 20000000000 && a.CandidateBytes != 50000000000 || a.Plan != "trial" && a.Plan != "paid" || a.Policy.Revision < 0 {
			return Page{}, ErrUnavailable
		}
		switch a.Policy.State {
		case "clear", "limited", "pending_apply", "pending_release", "apply_failed":
		default:
			return Page{}, ErrUnavailable
		}
		if a.Policy.Limited && (a.Policy.IncidentID == nil || a.Policy.UntilMS == nil || a.Incident == nil || *a.Policy.IncidentID != a.Incident.ID || a.Incident.AccountID != a.ID || *a.Policy.UntilMS <= page.GeneratedAtMS) {
			return Page{}, ErrUnavailable
		}
		previous = a.ID
	}
	if page.NextCursor != "" && (len(page.Items) == 0 || page.NextCursor != previous) {
		return Page{}, ErrUnavailable
	}
	return page, nil
}
func (c *Client) Release(ctx context.Context, account string, incident int64, actor string) (bool, error) {
	if !ValidID(account) || incident <= 0 || !ValidID(actor) {
		return false, ErrInvalid
	}
	var result struct {
		Released *bool `json:"released"`
	}
	err := c.request(ctx, "POST", "/admin/release", map[string]any{"account_id": account, "incident_id": incident, "actor": actor}, &result)
	if err != nil {
		return false, err
	}
	if result.Released == nil {
		return false, ErrUnavailable
	}
	return *result.Released, nil
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	type raw Policy
	var out raw
	var flags struct {
		Limited  *bool  `json:"limited"`
		Revision *int64 `json:"revision"`
	}
	if json.Unmarshal(data, &out) != nil || json.Unmarshal(data, &flags) != nil || flags.Limited == nil || flags.Revision == nil || out.RequiredNodes == nil || out.ConfirmedNodes == nil || out.FailedNodes == nil {
		return ErrUnavailable
	}
	*p = Policy(out)
	return nil
}
