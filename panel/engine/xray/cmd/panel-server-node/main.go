package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	xrayengine "salfetka/panel/engine/xray"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodeagent"
	"salfetka/panel/internal/nodesite"
	"salfetka/panel/internal/nodevpn"
	"salfetka/panel/internal/nodewire"
	"syscall"
	"time"
)

func run(ctx context.Context) error {
	if len(os.Args) == 3 && os.Args[1] == "site" {
		return nodesite.Serve(ctx, os.Args[2])
	}
	if len(os.Args) != 2 || (os.Args[1] != "initialize" && os.Args[1] != "run") {
		return errors.New("server_node_command_invalid")
	}
	expected := os.Getenv("PANEL_NODE_EXPECTED_ID")
	if expected == "" {
		return errors.New("server_node_identity_required")
	}
	lab := os.Getenv("PANEL_VPN_LAB_LOOPBACK_ONLY")
	if lab != "" && lab != "1" {
		return errors.New("server_node_lab_flag_invalid")
	}
	siteDir := filepath.Join(filepath.Dir(filepath.Dir(os.Getenv("PANEL_NODE_STATE_DIR"))), "site")
	agent, e := nodeagent.Open(nodeagent.Config{SiteDir: siteDir, StateDir: os.Getenv("PANEL_NODE_STATE_DIR"), PanelURL: os.Getenv("PANEL_NODE_PANEL_URL"), CAFile: os.Getenv("PANEL_NODE_CA_FILE"), SignerPublicFile: os.Getenv("PANEL_NODE_SIGNER_PUBLIC_FILE"), ExpectedNodeID: expected, Version: version})
	if e != nil {
		return e
	}
	defer agent.Close()
	id, signer, e := agent.VPNBinding()
	if e != nil {
		return e
	}
	material := func(c nodewire.ConnectionDeployment) (string, error) {
		if c.Configuration.Public.CertificateSource != "node" {
			return "", nil
		}
		cfg, err := nodesite.LoadConfig(siteDir)
		if err != nil || cfg.Domain != c.Configuration.Public.ServerName {
			return "", nodesite.ErrInvalid
		}
		cert, err := nodesite.Load(siteDir, cfg.Domain, time.Now())
		if err != nil {
			return "", err
		}
		if c.Configuration.Public.Template == connection.Reality {
			return "", nil
		}
		return cert.SHA256, nil
	}
	fleet, e := nodevpn.OpenFleet(nodevpn.FleetConfig{MaterialVersion: material, StateDir: os.Getenv("PANEL_FLEET_STATE_DIR"), NodeID: id, Signer: signer, Initialize: os.Args[1] == "initialize", Open: func(c nodewire.ConnectionDeployment, dir string, initialize bool) (nodevpn.FleetController, error) {
		backend := ""
		if c.Configuration.Public.Template == connection.Hy2 {
			backend = "hysteria2"
		}
		return nodevpn.Open(nodevpn.Config{Backend: backend, ProfileSHA256: connection.ProfileHash(c.Configuration.Public), StateDir: dir, NodeID: c.ID, InstallationID: c.InstallationID, ConfigSHA256: c.ConfigurationSHA256, Signer: signer, Initialize: initialize, Factory: func() (nodevpn.Engine, error) {
			resolved := c.Configuration
			if resolved.Public.CertificateSource == "node" && resolved.Public.Template != connection.Reality {
				cert, err := nodesite.Load(siteDir, resolved.Public.ServerName, time.Now())
				if err != nil {
					return nil, err
				}
				resolved.Public.CertificateSource = ""
				resolved.Private.CertificatePEM = cert.PEM
				resolved.Private.KeyPEM = cert.KeyPEM
			}
			return xrayengine.New(xrayengine.Config{Connection: &resolved, LabLoopbackOnly: lab == "1"})
		}})
	}})
	if e != nil {
		return e
	}
	defer fleet.Close()
	if os.Args[1] == "initialize" {
		return nil
	}
	return agent.RunFleet(ctx, fleet, func(code string) { slog.Warn("server_node_sync", "code", code) })
}

var version = "0.5.0-managed-connections"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := run(ctx); e != nil {
		slog.Error("server_node_failed", "code", e.Error())
		os.Exit(78)
	}
}
