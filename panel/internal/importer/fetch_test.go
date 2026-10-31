package importer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resolveFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolveFunc) LookupNetIP(c context.Context, n, h string) ([]netip.Addr, error) {
	return f(c, n, h)
}
func TestFetchPinsPublicDNSVerifiesTLSAndRejectsRebinding(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "https://example.com/ok")
			w.WriteHeader(302)
		case "/private":
			w.Header().Set("Location", "https://127.0.0.1/")
			w.WriteHeader(302)
		case "/gone":
			w.WriteHeader(404)
		case "/partial":
			w.WriteHeader(206)
			w.Write([]byte(testURI))
		case "/badexpiry":
			w.Header().Set("Subscription-Userinfo", "expire=1")
			w.Write([]byte(testURI))
		case "/huge":
			w.Write(bytes.Repeat([]byte{'x'}, MaxBytes+1))
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			g := gzip.NewWriter(w)
			g.Write(bytes.Repeat([]byte{'x'}, MaxBytes+1))
			g.Close()
		default:
			w.Write([]byte(testURI))
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	var lookups atomic.Int32
	f := fetcher{tls: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, resolver: resolveFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}), dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "93.184.216.34:443" {
			t.Error("unpinned dial")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	// httptest's trusted certificate covers example.com. No InsecureSkipVerify.
	r, e := f.fetch(context.Background(), "https://example.com/ok")
	if e != nil || string(r.Data) != testURI {
		t.Fatal("fetch", e)
	}
	before := lookups.Load()
	if _, e = f.fetch(context.Background(), "https://example.com/redirect"); e != nil || lookups.Load()-before != 2 {
		t.Fatal("redirect not revalidated", e)
	}
	for _, path := range []string{"/private", "/gone", "/partial", "/badexpiry", "/huge", "/gzip"} {
		if _, e = f.fetch(context.Background(), "https://example.com"+path); e == nil {
			t.Fatal("unsafe response accepted", path)
		}
	}
	if _, e = f.fetch(context.Background(), "https://wrong-certificate.example/ok"); e == nil {
		t.Fatal("TLS identity ignored")
	}
	count := calls.Load()
	f.resolver = resolveFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
	})
	if _, e = f.fetch(context.Background(), "https://example.com/ok"); e == nil || calls.Load() != count {
		t.Fatal("mixed DNS reached server")
	}
	var sequence int
	f.resolver = resolveFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		sequence++
		if sequence == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	})
	count = calls.Load()
	if _, e = f.fetch(context.Background(), "https://example.com/redirect"); e == nil || calls.Load() != count+1 {
		t.Fatal("DNS rebinding")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = f.fetch(ctx, "https://example.com/ok"); e == nil {
		t.Fatal("cancel ignored")
	}
}
func TestSourceURLAddressBoundaries(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://" + "user:password" + "@example.com", "https://example.com/#secret", "https://example.com:8443/", "https://localhost/", "https://x.localhost/", "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/", "https://100.64.0.1/", "https://[::ffff:8.8.8.8]/", "https://[64:ff9b::808:808]/"} {
		if ValidateURL(raw) == nil {
			t.Fatal("unsafe URL", strings.Split(raw, ":")[0])
		}
	}
	for _, ip := range []string{"0.1.2.3", "10.1.2.3", "192.168.1.1", "172.16.0.1", "198.18.0.1", "192.0.2.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "fc00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::1", "3fff::1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Fatal("reserved address")
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(ip)) {
			t.Fatal("public address")
		}
	}
}
func TestFetchDeadlineIncludesDNS(t *testing.T) {
	f := fetcher{resolver: resolveFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }), dial: func(context.Context, string, string) (net.Conn, error) { t.Fatal("unexpected dial"); return nil, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e := f.fetch(ctx, "https://example.com/")
	if e == nil || time.Since(start) > time.Second {
		t.Fatal("DNS deadline")
	}
}
