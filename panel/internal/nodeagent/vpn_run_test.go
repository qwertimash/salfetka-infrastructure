package nodeagent

import (
	"errors"
	"testing"
)

func TestVPNApplyDiagnosticDoesNotExposeEnginePayload(t *testing.T) {
	if vpnApplyCode(errors.New("vpn_engine_clock_untrusted")) != "vpn_engine_clock_untrusted" {
		t.Fatal("clock failure not distinguished")
	}
	if vpnApplyCode(errors.New("secret credential or arbitrary engine payload")) != "node_vpn_apply_failed" {
		t.Fatal("untrusted error reached diagnostic")
	}
}
