package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"salfetka/panel/internal/nodeagent"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "0.3.0-b3.3"

func run() error {
	if len(os.Args) != 2 || (os.Args[1] != "enroll" && os.Args[1] != "run" && os.Args[1] != "run-managed") {
		return commandError("node_command_requires_enroll_run_or_run_managed")
	}
	if os.Args[1] == "run-managed" && os.Getenv("PANEL_NODE_EXPECTED_ID") == "" {
		return commandError("node_expected_identity_required")
	}
	interval := 15
	if raw := os.Getenv("PANEL_NODE_HEARTBEAT_SECONDS"); raw != "" {
		var err error
		interval, err = strconv.Atoi(raw)
		if err != nil || interval < 1 || interval > 300 {
			return commandError("node_interval_invalid")
		}
	}
	agent, err := nodeagent.Open(nodeagent.Config{StateDir: os.Getenv("PANEL_NODE_STATE_DIR"), PanelURL: os.Getenv("PANEL_NODE_PANEL_URL"), CAFile: os.Getenv("PANEL_NODE_CA_FILE"), TokenFile: os.Getenv("PANEL_NODE_TOKEN_FILE"), SignerPublicFile: os.Getenv("PANEL_NODE_SIGNER_PUBLIC_FILE"), Version: version, ExpectedNodeID: os.Getenv("PANEL_NODE_EXPECTED_ID"), HeartbeatInterval: time.Duration(interval) * time.Second})
	if err != nil {
		return err
	}
	defer agent.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Args[1] == "enroll" {
		timeout, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err = agent.Enroll(timeout); err != nil {
			return err
		}
		slog.Info("node_enrollment_saved")
		return nil
	}
	return agent.Run(ctx, func(code string) {
		if code == "node_heartbeat_recorded" || code == "node_control_synchronized" {
			slog.Info(code)
		} else if strings.HasPrefix(code, "node_control_") {
			slog.Warn("node_control_failed", "code", code)
		} else {
			slog.Warn("node_heartbeat_failed", "code", code)
		}
	})
}

type commandError string

func (e commandError) Error() string { return string(e) }
func main() {
	if err := run(); err != nil {
		slog.Error("panel_node_failed", "code", err.Error())
		os.Exit(exitStatus(err))
	}
}

// Known configuration/identity/storage failures require an operator. The service
// manager must not turn a terminal denial into an unbounded restart loop.
func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	if strings.HasPrefix(err.Error(), "node_") {
		return 78
	}
	return 1
}
