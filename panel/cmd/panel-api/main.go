package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"salfetka/panel/internal/antifraud"
	"salfetka/panel/internal/appconfig"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/diagnostics"
	"salfetka/panel/internal/httpapi"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/secrets"
)

var version = "0.4.0-b4-dev"

func run() error {
	cfg, e := appconfig.LoadAPI()
	if e != nil {
		return e
	}
	vault, e := appconfig.LoadVault()
	if e != nil {
		return e
	}
	var authority *nodes.Authority
	var signer *nodecontrol.Signer
	if !cfg.DeliveryOnly {
		authority, e = appconfig.LoadNodeAuthority()
		if e != nil {
			return e
		}
		signer, e = appconfig.LoadNodeSigner()
		if e != nil {
			return e
		}
	}
	dsn, e := appconfig.DatabaseURL()
	if e != nil {
		return e
	}
	key, e := appconfig.PrivateFile(cfg.KeyFile)
	if e != nil {
		return errors.New("tls_key_invalid")
	}
	cert, e := os.ReadFile(cfg.CertFile)
	if e != nil {
		return errors.New("tls_certificate_invalid")
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return errors.New("tls_certificate_invalid")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, e := pgxpool.New(startup, dsn)
	if e != nil {
		return errors.New("database_configuration_failed")
	}
	defer pool.Close()
	if e = database.Ready(startup, pool); e != nil {
		return errors.New("database_not_ready_run_migrations")
	}
	if e = secrets.BindInstallation(startup, pool, vault); e != nil {
		return errors.New("installation_key_check_failed")
	}
	if !cfg.DeliveryOnly {
		if e = authority.Bind(startup, pool); e != nil {
			return errors.New("node_authority_check_failed")
		}
		if e = nodes.BindSigner(startup, pool, signer); e != nil {
			return errors.New("node_signer_check_failed")
		}
	}
	var diagnosticReader diagnostics.Reader
	if !cfg.DeliveryOnly {
		origin, keyFile := os.Getenv("PANEL_DIAGNOSTICS_ORIGIN"), os.Getenv("PANEL_DIAGNOSTICS_READ_KEY_FILE")
		if origin != "" || keyFile != "" {
			key, err := appconfig.PrivateFile(keyFile)
			if err != nil {
				return errors.New("diagnostics_key_invalid")
			}
			diagnosticReader, err = diagnostics.New(origin, strings.TrimSpace(string(key)))
			if err != nil {
				return err
			}
		}
	}
	var diagnosticInviter diagnostics.Inviter
	if !cfg.DeliveryOnly && os.Getenv("PANEL_DIAGNOSTICS_WRITE_KEY_FILE") != "" {
		key, err := appconfig.PrivateFile(os.Getenv("PANEL_DIAGNOSTICS_WRITE_KEY_FILE"))
		if err != nil {
			return errors.New("diagnostics_write_key_invalid")
		}
		diagnosticInviter, err = diagnostics.New(os.Getenv("PANEL_DIAGNOSTICS_ORIGIN"), strings.TrimSpace(string(key)))
		if err != nil {
			return err
		}
	}
	var antifraudService antifraud.Service
	if !cfg.DeliveryOnly {
		origin, keyFile := os.Getenv("PANEL_ANTIFRAUD_ORIGIN"), os.Getenv("PANEL_ANTIFRAUD_ADMIN_KEY_FILE")
		if origin != "" || keyFile != "" {
			key, err := appconfig.PrivateFile(keyFile)
			if err != nil {
				return errors.New("antifraud_key_invalid")
			}
			antifraudService, err = antifraud.New(origin, strings.TrimSpace(string(key)))
			if err != nil {
				return err
			}
		}
	}
	handler, e := httpapi.New(pool, httpapi.Config{Antifraud: antifraudService, Diagnostics: diagnosticReader, DiagnosticsInviter: diagnosticInviter, Origin: cfg.Origin, SubscriptionOrigin: cfg.SubscriptionOrigin, DeliveryOnly: cfg.DeliveryOnly, Static: os.DirFS(cfg.StaticDir), SessionTTL: cfg.SessionTTL, Logger: slog.Default(), BuildVersion: version, Vault: vault, NodeAuthority: authority, NodeSigner: signer, NodeInstallCA: cert, NodeInstallOrigin: cfg.NodeInstallOrigin})
	if e != nil {
		return errors.New("api_configuration_failed")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	if cfg.DeliveryOnly {
		// Public delivery certificates rotate independently of the pinned admin CA.
		reloader := &deliveryCertificate{certFile: cfg.CertFile, keyFile: cfg.KeyFile, pair: &pair}
		tlsConfig.Certificates = nil
		tlsConfig.GetCertificate = reloader.get
	}
	if authority != nil {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = authority.CertPool()
	}
	server := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384,
		TLSConfig: tlsConfig}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS("", "") }()
	slog.Info("panel_api_started", "version", version)
	select {
	case e = <-done:
		if !errors.Is(e, http.ErrServerClosed) {
			return errors.New("api_listener_failed")
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e = server.Shutdown(shutdown); e != nil {
			_ = server.Close()
			return errors.New("api_shutdown_failed")
		}
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		slog.Error("panel_api_failed", "code", e.Error())
		os.Exit(1)
	}
}
