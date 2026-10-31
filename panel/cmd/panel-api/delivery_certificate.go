package main

import (
	"crypto/tls"
	"log/slog"
	"os"
	"sync"
	"time"

	"salfetka/panel/internal/appconfig"
)

// Existing TLS connections keep their negotiated keys. A failed or partial file
// update keeps the last valid pair for new handshakes until a later retry.
type deliveryCertificate struct {
	mu                sync.Mutex
	certFile, keyFile string
	pair              *tls.Certificate
	nextRead          time.Time
}

func (c *deliveryCertificate) get(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.nextRead) {
		return c.pair, nil
	}
	c.nextRead = time.Now().Add(5 * time.Second)
	cert, err := os.ReadFile(c.certFile)
	if err == nil {
		var key []byte
		key, err = appconfig.PrivateFile(c.keyFile)
		if err == nil {
			var pair tls.Certificate
			pair, err = tls.X509KeyPair(cert, key)
			if err == nil {
				c.pair = &pair
			}
		}
	}
	if err != nil {
		slog.Warn("delivery_tls_reload_failed")
	}
	return c.pair, nil
}
