package xrayengine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"salfetka/panel/internal/database"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type serviceExit int

func (e serviceExit) Error() string { return fmt.Sprintf("owned_service_exit_%d", int(e)) }

type ownedService struct {
	name     string
	sentinel *exec.Cmd
}

func serviceCommand(args ...string) (string, error) {
	raw, e := exec.Command("sudo", append([]string{"systemctl"}, args...)...).Output()
	return strings.TrimSpace(string(raw)), e
}
func (s *ownedService) property(key string) string {
	v, _ := serviceCommand("show", s.name, "--property="+key, "--value")
	return v
}
func startOwnedService(t *testing.T, ctx context.Context, env []string, binary, dir string) (*ownedService, <-chan error) {
	t.Helper()
	if os.Geteuid() == 0 || !strings.HasPrefix(dir, "/var/lib/salfetka-b4-tests/") {
		t.Fatal("isolated unprivileged systemd fixture required")
	}
	source := os.Getenv("PANEL_B4_SYSTEMD_UNIT")
	raw, e := os.ReadFile(source)
	if e != nil {
		t.Fatal("packaged unit missing")
	}
	id, _ := database.NewID()
	name := "salfetka-b4-" + strings.ReplaceAll(id, "-", "")
	s := &ownedService{name: name + ".service"}
	var lines []string
	for _, value := range env {
		key, _, _ := strings.Cut(value, "=")
		switch key {
		case "PANEL_VPN_BACKEND", "PANEL_NODE_STATE_DIR", "PANEL_NODE_PANEL_URL", "PANEL_NODE_CA_FILE", "PANEL_NODE_SIGNER_PUBLIC_FILE", "PANEL_NODE_EXPECTED_ID", "PANEL_VPN_INSTALLATION_ID", "PANEL_VPN_STATE_DIR", "PANEL_VPN_LISTEN_IP", "PANEL_VPN_PORT", "PANEL_VPN_CERT_FILE", "PANEL_VPN_KEY_FILE", "PANEL_VPN_LAB_LOOPBACK_ONLY":
			lines = append(lines, value)
		}
	}
	envPath := filepath.Join(dir, "service.env")
	if e = os.WriteFile(envPath, []byte(strings.Join(lines, "\n")+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	unit := string(raw)
	replacements := map[string]string{
		"User=salfetka-vpn-node":                           "User=" + strconv.Itoa(os.Geteuid()),
		"Group=salfetka-vpn-node":                          "Group=" + strconv.Itoa(os.Getegid()),
		"EnvironmentFile=/etc/salfetka-vpn-node/agent.env": "EnvironmentFile=" + envPath,
		"ExecStart=/usr/local/libexec/salfetka-vpn-node/panel-vpn-node run-managed": "ExecStart=" + binary + " run-managed",
		"StateDirectory=salfetka-vpn-node":                                          "StateDirectory=" + name,
		"WorkingDirectory=/var/lib/salfetka-vpn-node":                               "WorkingDirectory=" + dir + "\nReadWritePaths=" + dir,
	}
	for before, after := range replacements {
		if !strings.Contains(unit, before) {
			t.Fatal("unit template drift")
		}
		unit = strings.Replace(unit, before, after, 1)
	}
	path := filepath.Join("/run/systemd/system", s.name)
	temp := filepath.Join(dir, "fixture.service")
	if e = os.WriteFile(temp, []byte(unit), 0600); e != nil {
		t.Fatal(e)
	}
	if exec.Command("sudo", "test", "-e", path).Run() == nil {
		t.Fatal("refusing foreign unit")
	}
	if e = exec.Command("sudo", "install", "-m", "0644", temp, path).Run(); e != nil {
		t.Fatal("install isolated unit")
	}
	t.Cleanup(func() {
		serviceCommand("stop", s.name)
		serviceCommand("clean", "--what=state", s.name)
		exec.Command("sudo", "rm", "--", path).Run()
		serviceCommand("daemon-reload")
		serviceCommand("reset-failed", s.name)
	})
	if e = exec.Command("sudo", "systemd-analyze", "verify", path).Run(); e != nil {
		t.Fatal("unit verify")
	}
	if _, e = serviceCommand("daemon-reload"); e != nil {
		t.Fatal("reload")
	}
	if _, e = serviceCommand("start", s.name); e != nil {
		t.Fatal("start owned service")
	}
	if s.property("NoNewPrivileges") != "yes" || s.property("KillMode") != "control-group" || s.property("User") != strconv.Itoa(os.Geteuid()) {
		t.Fatal("unit hardening missing")
	}
	s.sentinel = exec.Command("sleep", "180")
	if e = s.sentinel.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.sentinel.Process.Kill(); s.sentinel.Wait() })
	done := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				serviceCommand("stop", s.name)
				done <- nil
				return
			case <-time.After(200 * time.Millisecond):
			}
			state := s.property("ActiveState")
			if state == "failed" || state == "inactive" {
				code, _ := strconv.Atoi(s.property("ExecMainStatus"))
				done <- serviceExit(code)
				return
			}
		}
	}()
	return s, done
}
func (s *ownedService) crash(t *testing.T) {
	t.Helper()
	old := s.property("MainPID")
	if _, e := serviceCommand("kill", "--kill-whom=main", "--signal=SIGKILL", s.name); e != nil {
		t.Fatal("crash injection failed")
	}
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		if s.property("ActiveState") == "active" && s.property("MainPID") != "0" && s.property("MainPID") != old {
			if s.sentinel.Process.Signal(syscall.Signal(0)) != nil {
				t.Fatal("foreign process affected")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("supervisor did not recreate owned engine")
}
