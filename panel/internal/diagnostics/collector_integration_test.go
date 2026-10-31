package diagnostics

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Starts the real Python collector with a disposable SQLite DB and trusted test
// TLS. Exercises device commit/replay -> service read -> Go bridge without mocks.
func TestRealCollectorTLSAndDurableReplay(t *testing.T) {
	python := os.Getenv("DIAGNOSTIC_TEST_PYTHON")
	if python == "" {
		t.Skip("supply isolated collector Python runtime")
	}
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	pair := seed.TLS.Certificates[0]
	transport := seed.Client().Transport
	seed.Close()
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	encoded, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	program := `
import asyncio,json,ssl,sys,time
from pathlib import Path
from aiohttp import web
from mobile.lab.app import create_app
from mobile.lab.store import Store
from mobile.lab.tests.test_collector import HASH,activation,event
async def main():
 store=Store(Path(sys.argv[1])/'db');request,identity=activation(store)
 value=event('ping_trace',{'stage':'profile','network_error':'timeout','tls_started':1,'tls_finished':0},occurred_at_ms=int(time.time()*1000))
 first=store.ingest(request['device_token'],[value]);assert first==store.ingest(request['device_token'],[value])
 app=create_app(store,HASH,enforce_https=False,panel_read_key='ab'*32)
 runner=web.AppRunner(app,access_log=None);await runner.setup()
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[2],sys.argv[3])
 site=web.TCPSite(runner,'127.0.0.1',0,ssl_context=ctx);await site.start()
 print(json.dumps({'port':site._server.sockets[0].getsockname()[1],'tester':identity['tester_id']}),flush=True)
 await asyncio.Event().wait()
asyncio.run(main())
`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-u", "-c", program, dir, cert, key)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PYTHONPATH="+root)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("collector startup failed")
	}
	var ready struct {
		Port   json.Number `json:"port"`
		Tester string      `json:"tester"`
	}
	if json.Unmarshal(scanner.Bytes(), &ready) != nil {
		t.Fatal("collector startup invalid")
	}
	client, err := New("https://127.0.0.1:"+ready.Port.String(), strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	client.http.Transport = transport
	body, err := client.Read(ctx, ready.Tester, "")
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Events []struct {
			Kind    string         `json:"kind"`
			Payload map[string]any `json:"payload"`
		} `json:"events"`
	}
	if json.Unmarshal(body, &detail) != nil || len(detail.Events) != 1 || detail.Events[0].Kind != "ping_trace" || detail.Events[0].Payload["tls_finished"] != float64(0) {
		t.Fatal("committed event/replay projection mismatch")
	}
}
