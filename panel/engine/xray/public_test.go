package xrayengine

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVPNPublicHTTPSEgress(t *testing.T) {
	if os.Getenv("PANEL_B4_PUBLIC_PROBE") != "1" {
		t.Skip("explicit public network probe opt-in required")
	}
	ca := syntheticCert(t)
	port := freePort(t, false)
	r, e := New(Config{ListenIP: "127.0.0.1", Port: port, CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n")})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	apply(t, r, Grant{ID: users[0].Secret, Generation: 1, Enabled: true, Credential: users[0].Secret, ExpiresAt: time.Now().Add(time.Minute)})
	client := startClient(t, "vless_tls", port, ca, users[0])
	tcp, _ := echoes(t)
	check(t, !one(t, client, "tcp", tcp), "default public runtime allowed private egress")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, e := xcore.Dial(ctx, client.Instance, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if e != nil {
		t.Fatal("public dial failed")
	}
	defer conn.Close()
	secure := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com"})
	defer secure.Close()
	if e = secure.HandshakeContext(ctx); e != nil {
		t.Fatal("public TLS verification failed", e)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	done := make(chan error, 1)
	go func() {
		if e := req.Write(secure); e != nil {
			done <- e
			return
		}
		resp, e := http.ReadResponse(bufio.NewReader(secure), req)
		if e != nil {
			done <- e
			return
		}
		defer resp.Body.Close()
		_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
		if resp.StatusCode != 200 {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- e
	}()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("public HTTPS response failed")
		}
	case <-ctx.Done():
		secure.Close()
		<-done
		t.Fatal("public HTTPS timed out")
	}
	u, e := r.Usage(users[0].Secret)
	check(t, e == nil && u.Uplink != nil && *u.Uplink > 0 && u.Downlink != nil && *u.Downlink > 0, "public traffic counters absent")
	t.Log("verified public example.com HTTPS 200 through real VLESS/TLS; positive uplink/downlink; private egress remains blocked")
}

// Opt-in native probe of the exact private JSON downloaded by browser QA.
func TestDownloadedTrialPublicHTTPS(t *testing.T) {
	path := os.Getenv("PANEL_B4_TRIAL_CONFIG")
	if path == "" {
		t.Skip("private browser download required")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("absolute private config path required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("download unreadable")
	}
	defer clear(raw)
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("download invalid")
	}
	outbound, ok := config["outbounds"].([]any)
	if !ok || len(outbound) != 1 {
		t.Fatal("outbound count")
	}
	o := outbound[0].(map[string]any)
	var address any
	switch o["protocol"] {
	case "vless":
		address = o["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"]
	case "hysteria":
		address = o["settings"].(map[string]any)["address"]
	default:
		t.Fatal("unsupported managed backend")
	}
	if address != "127.0.0.1" {
		t.Fatal("probe only accepts owned loopback VPN node")
	}

	config["inbounds"].([]any)[0].(map[string]any)["port"] = freePort(t, false)
	client := startEngine(t, config)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, e := xcore.Dial(ctx, client.Instance, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if e != nil {
		t.Fatal("trial public dial failed")
	}
	defer conn.Close()
	secure := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com"})
	defer secure.Close()
	if e = secure.HandshakeContext(ctx); e != nil {
		t.Fatal("trial public TLS failed")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	done := make(chan error, 1)
	go func() {
		if e := req.Write(secure); e != nil {
			done <- e
			return
		}
		resp, e := http.ReadResponse(bufio.NewReader(secure), req)
		if e != nil {
			done <- e
			return
		}
		defer resp.Body.Close()
		_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
		if resp.StatusCode != 200 {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- e
	}()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("trial public response failed")
		}
	case <-ctx.Done():
		secure.Close()
		<-done
		t.Fatal("trial public timeout")
	}

	if marker := os.Getenv("PANEL_B4_RESTART_MARKER"); marker != "" {
		if !filepath.IsAbs(marker) {
			t.Fatal("marker must be absolute")
		}
		if e = os.WriteFile(marker+".ready", []byte("ready\n"), 0600); e != nil {
			t.Fatal(e)
		}
		for {
			if _, e = os.Stat(marker + ".continue"); e == nil {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("restart not confirmed")
			case <-time.After(50 * time.Millisecond):
			}
		}
		// Reuse the SAME VLESS TCP stream and TLS connection across API process restart.
		go func() {
			if e := req.Write(secure); e != nil {
				done <- e
				return
			}
			resp, e := http.ReadResponse(bufio.NewReader(secure), req)
			if e != nil {
				done <- e
				return
			}
			defer resp.Body.Close()
			_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
			if resp.StatusCode != 200 {
				done <- io.ErrUnexpectedEOF
				return
			}
			done <- e
		}()
		select {
		case e = <-done:
			if e != nil {
				t.Fatal("existing public flow failed across API restart")
			}
		case <-ctx.Done():
			secure.Close()
			<-done
			t.Fatal("post-restart HTTPS timeout")
		}
		t.Log("same live VLESS TCP/TLS flow carried public HTTPS before and after actual API process replacement")
	}
	t.Log("exact browser-downloaded trial config: public HTTPS 200 with TLS verification")
}
