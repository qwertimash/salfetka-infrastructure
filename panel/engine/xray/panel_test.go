package xrayengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	_ "github.com/xtls/xray-core/proxy/socks"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"salfetka/panel/internal/access"
	"salfetka/panel/internal/connection"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/httpapi"
	adminidentity "salfetka/panel/internal/identity"
	"salfetka/panel/internal/nodeagent"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/nodevpn"
	"salfetka/panel/internal/nodewire"
	"salfetka/panel/internal/secrets"
)

// A real HTTPS/mTLS API, PostgreSQL, unmodified polling agent and two real Xray
// clients. Business mutations go through authenticated public HTTP routes.
func TestPanelAgentRealTrafficRevokeAndRecovery(t *testing.T) { panelTraffic(t, false, false, false) }
func TestPanelVPNDaemonProcess(t *testing.T) {
	if os.Getenv("PANEL_VPN_PROCESS_BINARY") == "" {
		t.Skip("PANEL_VPN_PROCESS_BINARY required")
	}
	panelTraffic(t, true, false, false)
}
func TestPanelVPNOfflineLeaseRecovery(t *testing.T) {
	if os.Getenv("PANEL_B4_OFFLINE_TEST") != "1" {
		t.Skip("PANEL_B4_OFFLINE_TEST=1 required for 2-minute lease test")
	}
	panelTraffic(t, false, true, false)
}
func TestPanelVPNSystemdOwnedRecovery(t *testing.T) {
	if os.Getenv("PANEL_B4_SYSTEMD_TEST") != "1" {
		t.Skip("isolated Linux systemd opt-in required")
	}
	panelTraffic(t, true, false, true)
}
func TestPanelHysteriaRealTrafficRevoke(t *testing.T) {
	panelTraffic(t, false, false, false, "hysteria2")
}
func TestPanelHysteriaOfflineLease(t *testing.T) {
	if os.Getenv("PANEL_B4_OFFLINE_TEST") != "1" {
		t.Skip("offline opt-in required")
	}
	panelTraffic(t, false, true, false, "hysteria2")
}
func TestPanelHysteriaDaemon(t *testing.T) {
	if os.Getenv("PANEL_VPN_PROCESS_BINARY") == "" {
		t.Skip("daemon binary required")
	}
	panelTraffic(t, true, false, false, "hysteria2")
}
func TestPanelManagedNodeGRPCSubscriptionsAndRevoke(t *testing.T) {
	panelTraffic(t, false, false, false, "managed-grpc")
}
func panelTraffic(t *testing.T, process, offline, managed bool, backends ...string) {
	backend := ""
	if len(backends) > 0 {
		backend = backends[0]
	}
	fleetMode := backend == "managed-grpc"
	if fleetMode {
		backend = ""
	}
	pool := dbtest.New(t)
	ctx := context.Background()
	master := make([]byte, 32)
	rand.Read(master)
	vault, _ := secrets.New(master)
	bundle, _ := nodes.GenerateAuthority()
	authority, err := nodes.LoadAuthority(bundle)
	if err != nil {
		t.Fatal(err)
	}
	rawSigner, _ := nodecontrol.GenerateSigner()
	signer, _ := nodecontrol.LoadSigner(rawSigner)
	var handler atomic.Value
	var unavailable, dropACK atomic.Bool
	dropACK.Store(true)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/node/") && unavailable.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		h := handler.Load().(http.Handler)
		if r.URL.Path == nodewire.VPNReceiptsPath && dropACK.CompareAndSwap(true, false) {
			// The server commits, but the response is lost on the actual TLS connection.
			recorded := httptest.NewRecorder()
			h.ServeHTTP(recorded, r)
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		h.ServeHTTP(w, r)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: authority.CertPool()}
	server.StartTLS()
	defer server.Close()
	h, err := httpapi.New(pool, httpapi.Config{Origin: server.URL, Vault: vault, NodeAuthority: authority, NodeSigner: signer})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(h)
	store := adminidentity.New(pool, time.Hour)
	token, _ := adminidentity.RandomToken()
	if e := adminidentity.PrepareBootstrap(ctx, pool, adminidentity.TokenHash(token), time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e := store.Bootstrap(ctx, token, "owner", "synthetic-panel-vpn-test-739", "local"); e != nil {
		t.Fatal(e)
	}
	owner, err := store.Login(ctx, "owner", "synthetic-panel-vpn-test-739", "local")
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Timeout = 5 * time.Second
	seq := 0
	call := func(method, path string, body any, revision int64, want int, out any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, e := http.NewRequest(method, server.URL+path, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.AddCookie(&http.Cookie{Name: httpapi.CookieName, Value: owner.Token})
		req.Header.Set("Content-Type", "application/json")
		if method == "POST" {
			seq++
			req.Header.Set("Origin", server.URL)
			req.Header.Set("X-CSRF-Token", owner.CSRFToken)
			req.Header.Set("Idempotency-Key", fmt.Sprintf("panel-e2e-mutation-%08d", seq))
			if revision > 0 {
				req.Header.Set("If-Match", strconv.Quote(strconv.FormatInt(revision, 10)))
			}
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal("API request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s status=%d expected=%d", method, path, resp.StatusCode, want)
		}
		if out != nil {
			if e = json.NewDecoder(resp.Body).Decode(out); e != nil {
				t.Fatal(e)
			}
		}
	}
	var n nodes.Node
	if fleetMode {
		var machine nodes.Server
		call("POST", "/api/v1/servers", map[string]any{"name": "Managed loopback acceptance", "address": "127.0.0.1", "domain": "managed.example.com"}, 0, 200, &machine)
		call("POST", "/api/v1/managed/servers/"+machine.ID+"/node", map[string]any{}, 0, 200, &n)
	} else {
		call("POST", "/api/v1/nodes", map[string]any{"name": "VPN loopback acceptance"}, 0, 201, &n)
	}
	physicalID := n.ID
	var enrollment nodes.EnrollmentCreated
	call("POST", "/api/v1/nodes/"+n.ID+"/enrollment", map[string]any{}, n.Revision, 201, &enrollment)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, data, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	tokenJSON, _ := json.Marshal(enrollment.Enrollment)
	acfg := nodeagent.Config{StateDir: filepath.Join(dir, "agent"), PanelURL: server.URL, CAFile: write("api-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), TokenFile: write("enrollment.json", tokenJSON), SignerPublicFile: write("signer.pub", signer.PublicPEM()), Version: "b4-e2e"}
	agent, err := nodeagent.Open(acfg)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if e := agent.Enroll(ctx); e != nil {
		t.Fatal(e)
	}
	call("GET", "/api/v1/nodes/"+n.ID, nil, 0, 200, &n)
	installation, _ := database.NewID()
	if backend == "" && !fleetMode {
		call("POST", "/api/v1/nodes/"+n.ID+"/vpn", map[string]any{"installation_id": installation, "group_id": access.DefaultGroupID, "enabled": true}, n.Revision, 202, nil)
	}
	createUser := func(name string) access.Detail {
		var d access.Detail
		call("POST", "/api/v1/access/users", map[string]any{"name": name}, 0, 201, &d)
		path := "/api/v1/access/users/" + d.User.ID
		call("POST", path+"/entitlement", map[string]any{"action": "set", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "device_limit": 1, "group_id": access.DefaultGroupID}, d.User.Revision, 200, &d)
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		var challenge access.Challenge
		call("POST", path+"/devices/challenges", map[string]any{"public_key": base64.RawURLEncoding.EncodeToString(pub)}, d.User.Revision, 201, &challenge)
		call("POST", path+"/devices/register", map[string]any{"challenge_id": challenge.ID, "name": "Trial desktop", "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(challenge.SigningMessage)))}, challenge.UserRevision, 200, &d)
		return d
	}
	userA, userB := createUser("Acceptance A"), createUser("Acceptance B")
	ca := syntheticCert(t)
	port := freePort(t, backend == "hysteria2")
	tcp, udp := echoes(t)
	call("GET", "/api/v1/nodes/"+n.ID, nil, 0, 200, &n)
	if fleetMode {
		config := connection.Configuration{Public: connection.Spec{Template: connection.GRPC, Version: 1, Host: "127.0.0.1", ListenIP: "127.0.0.1", Port: port, ServerName: "b0.invalid", ServiceName: "vpn"}, Private: connection.PrivateMaterial{CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n")}}
		var batch nodes.ManagedBatch
		call("POST", "/api/v1/managed/nodes/"+n.ID+"/connections", map[string]any{"connections": []nodes.ManagedRequest{{Name: "Managed gRPC", GroupID: access.DefaultGroupID, Enabled: true, TrustedCAPEM: strings.Join(ca.root, "\n"), Configuration: config}}}, n.Revision, 200, &batch)
		installation = batch.Connections[0].VPN.InstallationID
		call("GET", "/api/v1/nodes/"+batch.Connections[0].ID, nil, 0, 200, &n)
	} else {
		call("POST", "/api/v1/nodes/"+n.ID+"/vpn", map[string]any{"installation_id": installation, "group_id": access.DefaultGroupID, "enabled": true, "endpoint": map[string]any{"backend": backend, "host": "127.0.0.1", "port": port, "server_name": "b0.invalid", "trusted_ca_pem": strings.Join(ca.root, "\n")}}, n.Revision, 202, nil)
	}

	_, pub, err := agent.VPNBinding()
	if err != nil {
		t.Fatal(err)
	}
	cfg := nodevpn.Config{Backend: backend, StateDir: filepath.Join(dir, "vpn"), NodeID: n.ID, InstallationID: installation, ConfigSHA256: strings.Repeat("a", 64), Signer: pub, Initialize: true, Factory: func() (nodevpn.Engine, error) {
		return New(Config{Backend: backend, ListenIP: "127.0.0.1", Port: port, CertificatePEM: strings.Join(ca.leaf, "\n"), KeyPEM: strings.Join(ca.key, "\n"), LabLoopbackOnly: true})
	}}

	runctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	var service *ownedService
	if process {
		agent.Close()
		binary := os.Getenv("PANEL_VPN_PROCESS_BINARY")
		env := append(os.Environ(), "PANEL_VPN_BACKEND="+backend, "PANEL_VPN_LAB_LOOPBACK_ONLY=1", "PANEL_NODE_STATE_DIR="+acfg.StateDir, "PANEL_NODE_PANEL_URL="+server.URL, "PANEL_NODE_CA_FILE="+acfg.CAFile, "PANEL_NODE_SIGNER_PUBLIC_FILE="+acfg.SignerPublicFile, "PANEL_NODE_EXPECTED_ID="+n.ID, "PANEL_VPN_INSTALLATION_ID="+installation, "PANEL_VPN_STATE_DIR="+cfg.StateDir, "PANEL_VPN_LISTEN_IP=127.0.0.1", fmt.Sprintf("PANEL_VPN_PORT=%d", port), "PANEL_VPN_CERT_FILE="+write("vpn.crt", []byte(strings.Join(ca.leaf, "\n"))), "PANEL_VPN_KEY_FILE="+write("vpn.key", []byte(strings.Join(ca.key, "\n"))))
		init := exec.CommandContext(runctx, binary, "initialize")
		init.Env = env
		if e := init.Run(); e != nil {
			t.Fatal("daemon initialize", e)
		}
		if managed {
			var stopped <-chan error
			service, stopped = startOwnedService(t, runctx, env, binary, dir)
			go func() { done <- <-stopped }()
		} else {
			cmd := exec.CommandContext(runctx, binary, "run-managed")
			cmd.Env = env
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			go func() { done <- cmd.Wait() }()
		}
	} else if fleetMode {
		f, e := nodevpn.OpenFleet(nodevpn.FleetConfig{StateDir: filepath.Join(dir, "fleet"), NodeID: physicalID, Signer: pub, Initialize: true, Open: func(d nodewire.ConnectionDeployment, path string, initialize bool) (nodevpn.FleetController, error) {
			return nodevpn.Open(nodevpn.Config{ProfileSHA256: connection.ProfileHash(d.Configuration.Public), StateDir: path, NodeID: d.ID, InstallationID: d.InstallationID, ConfigSHA256: d.ConfigurationSHA256, Signer: pub, Initialize: initialize, Factory: func() (nodevpn.Engine, error) {
				return New(Config{Connection: &d.Configuration, LabLoopbackOnly: true})
			}})
		}})
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		go func() { done <- agent.RunFleet(runctx, f, nil) }()
	} else {
		c, e := nodevpn.Open(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		go func() { done <- agent.RunVPN(runctx, installation, c, nil) }()
	}
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("agent cleanup blocked")
		}
	}()
	read := func() nodes.VPNStatus {
		var s nodes.VPNStatus
		call("GET", "/api/v1/nodes/"+n.ID+"/vpn", nil, 0, 200, &s)
		return s
	}
	wait := func(pred func(nodes.VPNStatus) bool) nodes.VPNStatus {
		t.Helper()
		until := time.Now().Add(25 * time.Second)
		for time.Now().Before(until) {
			s := read()
			if pred(s) {
				return s
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("observed state did not converge")
		return nodes.VPNStatus{}
	}
	initial := wait(func(s nodes.VPNStatus) bool { return s.State == "applied" })

	configs := map[string]map[string]any{}
	freshClient := func(id string) *engine {
		raw, _ := json.Marshal(configs[id])
		var config map[string]any
		json.Unmarshal(raw, &config)
		config["inbounds"].([]any)[0].(map[string]any)["port"] = freePort(t, false)
		return startEngine(t, config)
	}
	export := func(user access.Detail) *engine {
		var config map[string]any
		call("POST", "/api/v1/access/users/"+user.User.ID+"/devices/"+user.Devices[0].ID+"/vpn-config", map[string]any{"node_id": n.ID}, 0, 200, &config)
		// Only the local SOCKS port changes to avoid colliding with the second client.
		// The downloaded outbound and TLS verification remain byte-for-byte equivalent.
		config["inbounds"].([]any)[0].(map[string]any)["port"] = freePort(t, false)
		configs[user.User.ID] = config
		return startEngine(t, config)
	}
	a, b := export(userA), export(userB)
	var personalTCP, personalUDP *flow
	personalURL := ""
	if !managed {
		personalTCP, personalUDP, personalURL = personalSubscriptionFlow(t, client, call, userA, n.ID, tcp, udp)
	}
	at, au := openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
	bt, bu := openFlow(t, b, "tcp", tcp), openFlow(t, b, "udp", udp)
	check(t, at.exchange([]byte("panel-A")) && au.exchange([]byte("panel-A-udp")) && bt.exchange([]byte("panel-B")) && bu.exchange([]byte("panel-B-udp")), "panel-issued access did not connect")
	measured := wait(func(s nodes.VPNStatus) bool {
		if s.Observed == nil {
			return false
		}
		for _, u := range s.Observed.Usage {
			if u.GrantID == userA.Devices[0].Credential.ID && u.Uplink != nil && *u.Uplink > 0 && u.Downlink != nil && *u.Downlink > 0 {
				return true
			}
		}
		return false
	})
	check(t, measured.Observed.Sequence > initial.Observed.Sequence, "lost ACK blocked further samples")

	if managed {
		oldEpoch := read().Observed.EngineEpoch
		unavailable.Store(true)
		service.crash(t)
		// A killed QUIC process cannot send a close packet; denial may surface as timeout.
		check(t, !at.exchange([]byte("crashed")) && (backend == "hysteria2" || at.outcome != "timeout") && !one(t, b, "tcp", tcp), "crash restored saved policy without authorization")
		if backend == "hysteria2" {
			check(t, !one(t, freshClient(userB.User.ID), "tcp", tcp), "fresh QUIC client accepted saved policy while API offline")
		}
		unavailable.Store(false)
		wait(func(s nodes.VPNStatus) bool { return s.State == "applied" && s.Observed.EngineEpoch != oldEpoch })
		if backend == "hysteria2" {
			a, b = freshClient(userA.User.ID), freshClient(userB.User.ID)
		}
		at, au = openFlow(t, a, "tcp", tcp), openFlow(t, a, "udp", udp)
		bt, bu = openFlow(t, b, "tcp", tcp), openFlow(t, b, "udp", udp)
		check(t, at.exchange([]byte("fresh-A")) && au.exchange([]byte("fresh-A-udp")) && bt.exchange([]byte("fresh-B")) && bu.exchange([]byte("fresh-B-udp")), "fresh epoch failed to reconnect")
		t.Log("packaged systemd hardening + SIGKILL: owned engine recreated, foreign process intact, saved grants denied while API offline, fresh signed epoch restores access")
	}
	unavailable.Store(true)
	time.Sleep(6 * time.Second)
	check(t, at.exchange([]byte("api-outage-A")) && bt.exchange([]byte("api-outage-B")), "transient API outage killed leases")
	unavailable.Store(false)
	revokedAt := time.Now()
	call("POST", "/api/v1/access/users/"+userA.User.ID+"/state", map[string]any{"state": "suspended"}, userA.User.Revision, 200, &userA)
	wait(func(s nodes.VPNStatus) bool {
		return s.State == "applied" && s.DesiredGeneration > initial.DesiredGeneration && len(s.Observed.Usage) == 1 && s.Observed.Usage[0].GrantID == userB.Devices[0].Credential.ID
	})
	check(t, !at.exchange([]byte("revoked-A")) && !au.exchange([]byte("revoked-A-udp")) && at.outcome != "timeout" && au.outcome != "timeout", "active A was not explicitly terminated")
	check(t, !one(t, a, "tcp", tcp) && !one(t, a, "udp", udp), "saved A credentials still accepted")
	if personalTCP != nil {
		check(t, !personalTCP.exchange([]byte("personal-revoked")) && !personalUDP.exchange([]byte("personal-revoked-udp")) && personalTCP.outcome != "timeout" && personalUDP.outcome != "timeout", "personal active streams were not explicitly revoked")
		response, e := client.Get(personalURL)
		if e != nil {
			t.Fatal("revoked personal URL request failed")
		}
		response.Body.Close()
		check(t, response.StatusCode == 404, "revoked personal URL still delivered")
		t.Log("personal subscription: active TCP/UDP revoked, subsequent download denied, unrelated customer retained")
	}
	check(t, bt.exchange([]byte("preserved-B")) && bu.exchange([]byte("preserved-B-udp")) && one(t, b, "tcp", tcp) && one(t, b, "udp", udp), "A revocation affected B")
	check(t, time.Since(revokedAt) < 30*time.Second, "online revoke exceeded bound")

	if offline {
		state := read()
		unavailable.Store(true)
		// Wait the actual server-issued absolute lease, without manipulating clocks
		// or the runtime timeout. HTTP control errors cannot extend this deadline.
		waitFor := time.Until(*state.PolicyExpiresAt) + 300*time.Millisecond
		t.Logf("waiting actual offline lease: %s", waitFor.Round(time.Second))
		if waitFor > 0 {
			time.Sleep(waitFor)
		}
		check(t, !bt.exchange([]byte("offline-expired")) && !bu.exchange([]byte("offline-expired-udp")) && bt.outcome != "timeout" && bu.outcome != "timeout", "offline lease failed to terminate flows")
		check(t, !one(t, b, "tcp", tcp) && !one(t, b, "udp", udp), "offline saved config admitted")
		check(t, read().State == "stale", "offline state falsely fresh")
		unavailable.Store(false)
		wait(func(s nodes.VPNStatus) bool {
			return s.State == "applied" && s.DesiredGeneration > state.DesiredGeneration
		})
		bt, bu = openFlow(t, b, "tcp", tcp), openFlow(t, b, "udp", udp)
		check(t, bt.exchange([]byte("auto-recovered")) && bu.exchange([]byte("auto-recovered-udp")), "fresh authorization failed to restore without reconnecting service")
	}
	// Public node revoke is checked even on an existing mTLS connection.
	if fleetMode {
		n.ID = physicalID
	}
	call("GET", "/api/v1/nodes/"+n.ID, nil, 0, 200, &n)
	call("POST", "/api/v1/nodes/"+n.ID+"/revoke", map[string]any{}, n.Revision, 200, nil)
	select {
	case err = <-done:
		if managed {
			check(t, err == serviceExit(78), "revoked service did not stop terminally")
		} else if process {
			exit, ok := err.(*exec.ExitError)
			check(t, ok && exit.ExitCode() == 78, "revoked daemon did not stop terminally")
		} else {
			check(t, err != nil && err.Error() == "node_authorization_rejected", "node revoke did not terminate loop")
		}
		done <- err
	case <-time.After(20 * time.Second):
		t.Fatal("node revoke did not close engine")
	}
	check(t, !bt.exchange([]byte("revoked-node-B")) && bt.outcome != "timeout", "node revoke left active engine")
	t.Log("real API + PostgreSQL + mTLS polling + owned Xray: two clients TCP/UDP, cumulative observed traffic, lost ACK recovery, transient API outage, online A revoke under 30s with B preserved, node revoke closes engine")
}

func TestPanelHysteriaSystemdOwnedRecovery(t *testing.T) {
	if os.Getenv("PANEL_B4_SYSTEMD_TEST") != "1" {
		t.Skip("isolated Linux systemd opt-in required")
	}
	panelTraffic(t, true, false, true, "hysteria2")
}
