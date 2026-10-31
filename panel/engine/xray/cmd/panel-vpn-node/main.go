package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	xrayengine "salfetka/panel/engine/xray"
	"salfetka/panel/internal/nodeagent"
	"salfetka/panel/internal/nodevpn"
)

func runOnce(ctx context.Context) error {
	if len(os.Args) != 2 || (os.Args[1] != "initialize" && os.Args[1] != "run-managed") {
		return errors.New("vpn_command_invalid")
	}
	if os.Getenv("PANEL_NODE_EXPECTED_ID") == "" {
		return errors.New("vpn_expected_identity_required")
	}
	port, err := strconv.Atoi(os.Getenv("PANEL_VPN_PORT"))
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("vpn_unprivileged_port_required")
	}
	cert, key, err := nodevpn.LoadTLSMaterial(os.Getenv("PANEL_VPN_CERT_FILE"), os.Getenv("PANEL_VPN_KEY_FILE"))
	if err != nil {
		return err
	}
	lab := os.Getenv("PANEL_VPN_LAB_LOOPBACK_ONLY")
	if lab != "" && lab != "1" {
		return errors.New("vpn_lab_flag_invalid")
	}
	config := xrayengine.Config{Backend: os.Getenv("PANEL_VPN_BACKEND"), LabLoopbackOnly: lab == "1", ListenIP: os.Getenv("PANEL_VPN_LISTEN_IP"), Port: port, CertificatePEM: cert, KeyPEM: key}
	// The closed typed configuration, including TLS identity, is installation-bound.
	raw, _ := json.Marshal(config)
	sum := sha256.Sum256(raw)
	clear(raw)
	agent, err := nodeagent.Open(nodeagent.Config{StateDir: os.Getenv("PANEL_NODE_STATE_DIR"), PanelURL: os.Getenv("PANEL_NODE_PANEL_URL"), CAFile: os.Getenv("PANEL_NODE_CA_FILE"), SignerPublicFile: os.Getenv("PANEL_NODE_SIGNER_PUBLIC_FILE"), ExpectedNodeID: os.Getenv("PANEL_NODE_EXPECTED_ID"), Version: "0.4.0-b4-dev"})
	if err != nil {
		return err
	}
	defer agent.Close()
	id, signer, err := agent.VPNBinding()
	if err != nil {
		return err
	}
	installation := os.Getenv("PANEL_VPN_INSTALLATION_ID")
	controller, err := nodevpn.Open(nodevpn.Config{Backend: config.Backend, StateDir: os.Getenv("PANEL_VPN_STATE_DIR"), NodeID: id, InstallationID: installation, ConfigSHA256: hex.EncodeToString(sum[:]), Signer: signer, Initialize: os.Args[1] == "initialize", Factory: func() (nodevpn.Engine, error) { return xrayengine.New(config) }})
	if err != nil {
		return err
	}
	defer controller.Close()
	if os.Args[1] == "initialize" {
		slog.Info("vpn_installation_initialized")
		return nil
	}
	return agent.RunVPN(ctx, installation, controller, func(code string) {
		if code == "node_vpn_synchronized" || code == "node_heartbeat_recorded" {
			slog.Info(code)
		} else {
			slog.Warn("vpn_synchronization_failed", "code", code)
		}
	})
}

func recoverableClock(err error) bool {
	if err == nil {
		return false
	}
	switch err.Error() {
	case "vpn_clock_untrusted", "vpn_engine_clock_untrusted", "node_clock_untrusted":
		return true
	}
	return false
}

// Each attempt fully closes its engine/agent and reopens durable ownership/HWM.
// Clock recovery never replays a saved policy or relaxes an absolute deadline.
func supervise(ctx context.Context, attempt func(context.Context) error, delay time.Duration, report func()) error {
	for ctx.Err() == nil {
		err := attempt(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if !recoverableClock(err) {
			return err
		}
		report()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) != 2 || os.Args[1] != "run-managed" {
		return runOnce(ctx)
	}
	return supervise(ctx, runOnce, 5*time.Second, func() {
		slog.Warn("vpn_clock_recovery_wait", "fresh_authorization_required", true)
	})
}
func main() {
	if err := run(); err != nil {
		slog.Error("vpn_node_failed", "code", err.Error())
		os.Exit(78)
	}
}
