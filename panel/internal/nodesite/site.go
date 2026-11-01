// Package nodesite owns only a static website and its read-only TLS bundle.
// ACME and private-key writes belong to the privileged installer, never the agent.
package nodesite

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var ErrInvalid = errors.New("node_site_invalid")
var token = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

type Config struct {
	Domain string `json:"domain"`
}
type Certificate struct {
	Pair      tls.Certificate
	PEM       string
	KeyPEM    string
	SHA256    string
	ExpiresAt time.Time
}

func Read(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0022 != 0 {
		return nil, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}
func LoadConfig(dir string) (Config, error) {
	var c Config
	raw, err := Read(filepath.Join(dir, "config.json"), 4096)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.Decode(new(any)) != io.EOF || !hostname.MatchString(c.Domain) || !strings.Contains(c.Domain, ".") || net.ParseIP(c.Domain) != nil {
		return c, ErrInvalid
	}
	return c, nil
}
func Load(dir, domain string, now time.Time) (Certificate, error) {
	var out Certificate
	raw, err := Read(filepath.Join(dir, "bundle.pem"), 65536)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	pair, err := tls.X509KeyPair(raw, raw)
	if err != nil || len(pair.Certificate) == 0 {
		return out, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(domain) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return out, ErrInvalid
	}
	pair.Leaf = leaf
	out.Pair = pair
	out.ExpiresAt = leaf.NotAfter
	digest := sha256.Sum256(pair.Certificate[0])
	out.SHA256 = hex.EncodeToString(digest[:])
	for _, der := range pair.Certificate {
		out.PEM += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return Certificate{}, ErrInvalid
	}
	out.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	clear(key)
	return out, nil
}

const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Field notes</title><style>body{margin:0;background:#f4f1ea;color:#25352d;font:18px/1.6 Georgia,serif}main{max-width:720px;margin:12vh auto;padding:32px}small{font:12px system-ui;letter-spacing:.2em}h1{font-size:clamp(40px,8vw,76px);line-height:1.1;font-weight:normal}article{border-top:1px solid #b4bbae;margin-top:48px;padding-top:24px}footer{margin-top:64px;font:12px system-ui;color:#617065}</style><main><small>FIELD NOTES</small><h1>A little room<br>for perspective.</h1><p>Observations on quiet places, everyday details, and the things we notice when we slow down.</p><article><small>01 / OBSERVATIONS</small><h2>Light through the trees</h2><p>A walk does not need a destination. Sometimes the best part is the changing light, a familiar path, and a moment to look around.</p></article><footer>A collection of small observations.</footer></main></html>`

func Handler(domain, webroot string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(405)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		const prefix = "/.well-known/acme-challenge/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			name := strings.TrimPrefix(r.URL.Path, prefix)
			if !token.MatchString(name) || r.URL.RawPath != "" || r.URL.RawQuery != "" {
				http.NotFound(w, r)
				return
			}
			// Challenges are public and shared with panel ACME in combined mode.
			// No file server, symlinks, directory indexes or arbitrary paths.
			raw, err := Read(filepath.Join(webroot, ".well-known/acme-challenge", name), 4096)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-store")
			if r.Method == "GET" {
				w.Write(raw)
			}
			return
		}
		if host != domain {
			http.Error(w, "Not found", 404)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == "GET" {
			io.WriteString(w, page)
		}
	})
}

func TLS(dir, domain string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != domain {
			return nil, ErrInvalid
		}
		cert, err := Load(dir, domain, time.Now())
		if err != nil {
			return nil, err
		}
		return &cert.Pair, nil
	}}
}

// Probe proves the owned site's TLS listener serves this exact certificate.
// A file on disk alone is not a successful website deployment.
func Probe(domain string, cert Certificate) error {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(cert.PEM))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:8445", &tls.Config{RootCAs: roots, ServerName: domain, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	if err != nil {
		return ErrInvalid
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" || len(state.PeerCertificates) == 0 {
		return ErrInvalid
	}
	digest := sha256.Sum256(state.PeerCertificates[0].Raw)
	if hex.EncodeToString(digest[:]) != cert.SHA256 {
		return ErrInvalid
	}
	return nil
}

func Serve(ctx context.Context, dir string) error {
	c, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	// Reserve both sockets before serving either. Never stop an existing listener.
	plain, err := net.Listen("tcp", ":80")
	if err != nil {
		return errors.New("node_site_http_port_busy")
	}
	defer plain.Close()
	secure, err := net.Listen("tcp", ":8445")
	if err != nil {
		return errors.New("node_site_https_port_busy")
	}
	defer secure.Close()
	handler := Handler(c.Domain, filepath.Join(dir, "webroot"))
	makeServer := func() *http.Server {
		return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	}
	httpServer, httpsServer := makeServer(), makeServer()
	httpsServer.TLSConfig = TLS(dir, c.Domain)
	defer httpServer.Close()
	defer httpsServer.Close()
	done := make(chan error, 2)
	go func() { done <- httpServer.Serve(plain) }()
	go func() { done <- httpsServer.ServeTLS(secure, "", "") }()
	select {
	case <-ctx.Done():
		return nil
	case <-done:
		return errors.New("node_site_listener_failed")
	}
}
