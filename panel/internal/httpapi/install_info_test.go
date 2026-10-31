package httpapi

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"salfetka/panel/internal/nodecontrol"
	"salfetka/panel/internal/nodes"
	"testing"
)

func TestInstallInfoPinsPublicTrustAndRejectsWrongOrigin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	key, e := nodecontrol.GenerateSigner()
	if e != nil {
		t.Fatal(e)
	}
	signer, e := nodecontrol.LoadSigner(key)
	if e != nil {
		t.Fatal(e)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	a := api{config: Config{Origin: server.URL, NodeSigner: signer, NodeInstallCA: cert}}
	value, e := a.installInfo()
	if e != nil {
		t.Fatal(e)
	}
	info := value.(map[string]any)
	if info["panel_url"] != server.URL || info["signer_pem"] != string(signer.PublicPEM()) || info["ca_pem"] != string(cert) {
		t.Fatal("trust metadata changed")
	}
	a.config.Origin = "https://wrong.example.invalid"
	if _, e = a.installInfo(); !errors.Is(e, nodes.ErrKey) {
		t.Fatal("wrong TLS origin accepted")
	}
	a.config.NodeInstallOrigin = server.URL
	value, e = a.installInfo()
	if e != nil || value.(map[string]any)["panel_url"] != server.URL {
		t.Fatal("dedicated machine origin not used")
	}
	a.config.NodeInstallOrigin = "https://wrong.example.invalid"
	if _, e = a.installInfo(); !errors.Is(e, nodes.ErrKey) {
		t.Fatal("wrong machine TLS origin accepted")
	}
	a.config.NodeInstallCA = nil
	if _, e = a.installInfo(); !errors.Is(e, nodes.ErrKey) {
		t.Fatal("missing trust accepted")
	}
}
