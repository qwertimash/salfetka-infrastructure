package importer

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type FetchResult struct {
	Data      []byte
	ExpiresAt *time.Time
	Userinfo  []string
}
type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type fetcher struct {
	resolver resolver
	dial     func(context.Context, string, string) (net.Conn, error)
	tls      *tls.Config
}

var denied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("168.63.129.16/32"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func publicIP(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, p := range denied {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// ValidateURL checks syntax only. DNS and all addresses are rechecked before
// every redirect and every dial, then the selected numeric address is pinned.
func ValidateURL(raw string) error {
	if len(raw) > 8192 || !validText(raw, 8192) {
		return Error("source_url")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.Contains(u.Hostname(), "%") || u.Port() != "" && u.Port() != "443" {
		return Error("source_url")
	}
	if a, e := netip.ParseAddr(u.Hostname()); e == nil && !publicIP(a) {
		return Error("source_address_denied")
	}
	if strings.HasSuffix(strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), ".localhost") || strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), "localhost") {
		return Error("source_address_denied")
	}
	return nil
}
func Fetch(ctx context.Context, raw string) (FetchResult, error) {
	f := fetcher{resolver: net.DefaultResolver, dial: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	return f.fetch(ctx, raw)
}
func (f fetcher) fetch(ctx context.Context, raw string) (FetchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 * 1024, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, TLSClientConfig: f.tls}
	defer t.CloseIdleConnections()
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		hostname, port, e := net.SplitHostPort(address)
		if e != nil || port != "443" {
			return nil, Error("source_address_denied")
		}
		addresses, e := f.resolver.LookupNetIP(ctx, "ip", hostname)
		if e != nil || len(addresses) == 0 || len(addresses) > 32 {
			return nil, Error("source_dns_failed")
		}
		for _, a := range addresses {
			if !publicIP(a) {
				return nil, Error("source_address_denied")
			}
		}
		// No second resolution occurs between validation and connection; TLS still
		// authenticates the original URL host. A new redirect gets a fresh transport dial.
		return f.dial(ctx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	client := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for redirects := 0; redirects <= 3; redirects++ {
		if e := ValidateURL(raw); e != nil {
			return FetchResult{}, e
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if e != nil {
			return FetchResult{}, Error("source_url")
		}
		req.Header.Set("Accept", "application/json, text/plain")
		req.Header.Set("User-Agent", "Salfetka-Source/1")
		res, e := client.Do(req)
		if e != nil {
			return FetchResult{}, Error("source_fetch_failed")
		}
		if member(strconv.Itoa(res.StatusCode), "301", "302", "303", "307", "308") {
			location := res.Header.Get("Location")
			res.Body.Close()
			if redirects == 3 || location == "" {
				return FetchResult{}, Error("source_redirect")
			}
			next, e := req.URL.Parse(location)
			if e != nil {
				return FetchResult{}, Error("source_redirect")
			}
			raw = next.String()
			continue
		}
		if res.StatusCode != 200 || res.Header.Get("Content-Range") != "" {
			res.Body.Close()
			return FetchResult{}, Error("source_http_status")
		}
		if res.ContentLength > MaxBytes {
			res.Body.Close()
			return FetchResult{}, Error("source_size")
		}
		data, e := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
		res.Body.Close()
		if e != nil {
			return FetchResult{}, Error("source_fetch_failed")
		}
		if len(data) > MaxBytes {
			return FetchResult{}, Error("source_size")
		}
		encoding := strings.ToLower(res.Header.Get("Content-Encoding"))
		if encoding == "gzip" {
			g, e := gzip.NewReader(strings.NewReader(string(data)))
			if e != nil {
				return FetchResult{}, Error("source_encoding")
			}
			data, e = io.ReadAll(io.LimitReader(g, MaxBytes+1))
			g.Close()
			if e != nil {
				return FetchResult{}, Error("source_encoding")
			}
			if len(data) > MaxBytes {
				return FetchResult{}, Error("source_size")
			}
		} else if encoding != "" && encoding != "identity" {
			return FetchResult{}, Error("source_encoding")
		}
		var expiry *time.Time
		// Subscription-Userinfo can carry source expiry independently of the body.
		// Ambiguous or invalid expiry is an error, never a new unlimited entitlement.
		seen := false
		for _, header := range res.Header.Values("Subscription-Userinfo") {
			for _, part := range strings.Split(header, ";") {
				k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
				if k != "expire" {
					continue
				}
				if seen || !ok {
					return FetchResult{}, Error("source_expiry_header")
				}
				seen = true
				n, e := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				if e != nil || n <= 0 {
					return FetchResult{}, Error("source_expiry_header")
				}
				t := time.Unix(n, 0).UTC()
				if !t.After(time.Now()) {
					return FetchResult{}, Error("source_expired")
				}
				expiry = &t
			}
		}
		return FetchResult{Data: data, ExpiresAt: expiry, Userinfo: append([]string(nil), res.Header.Values("Subscription-Userinfo")...)}, nil
	}
	return FetchResult{}, Error("source_redirect")
}
