package main

import (
	"errors"
	"testing"
)

func TestTerminalFailuresDoNotRestart(t *testing.T) {
	for _, code := range []string{"node_authorization_rejected", "node_certificate_expired", "node_clock_untrusted", "node_control_storage_failed", "node_expected_identity_mismatch", "node_state_busy"} {
		if exitStatus(errors.New(code)) != 78 {
			t.Fatal(code)
		}
	}
	if exitStatus(nil) != 0 || exitStatus(errors.New("unexpected runtime failure")) != 1 {
		t.Fatal("exit classification")
	}
}
