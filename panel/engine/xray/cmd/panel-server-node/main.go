package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	xrayengine "salfetka/panel/engine/xray"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/nodeagent"
	"salfetka/panel/internal/nodevpn"
	"salfetka/panel/internal/nodewire"
	"syscall"
)

func run(ctx context.Context) error {
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
	agent, e := nodeagent.Open(nodeagent.Config{StateDir: os.Getenv("PANEL_NODE_STATE_DIR"), PanelURL: os.Getenv("PANEL_NODE_PANEL_URL"), CAFile: os.Getenv("PANEL_NODE_CA_FILE"), SignerPublicFile: os.Getenv("PANEL_NODE_SIGNER_PUBLIC_FILE"), ExpectedNodeID: expected, Version: version})
	if e != nil {
		return e
	}
	defer agent.Close()
	id, signer, e := agent.VPNBinding()
	if e != nil {
		return e
	}
	fleet, e := nodevpn.OpenFleet(nodevpn.FleetConfig{StateDir: os.Getenv("PANEL_FLEET_STATE_DIR"), NodeID: id, Signer: signer, Initialize: os.Args[1] == "initialize", Open: func(c nodewire.ConnectionDeployment, dir string, initialize bool) (nodevpn.FleetController, error) {
		backend := ""
		if c.Configuration.Public.Template == connection.Hy2 {
			backend = "hysteria2"
		}
		return nodevpn.Open(nodevpn.Config{Backend: backend, ProfileSHA256: connection.ProfileHash(c.Configuration.Public), StateDir: dir, NodeID: c.ID, InstallationID: c.InstallationID, ConfigSHA256: c.ConfigurationSHA256, Signer: signer, Initialize: initialize, Factory: func() (nodevpn.Engine, error) {
			return xrayengine.New(xrayengine.Config{Connection: &c.Configuration, LabLoopbackOnly: lab == "1"})
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
