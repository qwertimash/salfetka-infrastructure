package main

import "testing"

func TestRestoreRuntimeRoleNamesStayInOwnedNamespace(t *testing.T) {
	for _, role := range []string{"panel_runtime", "panel_runtime_restore_012345abcdef"} {
		if !validRuntimeRole(role) {
			t.Fatal("valid dedicated role rejected")
		}
	}
	for _, role := range []string{"postgres", "panel_migrator", "panel_runtime_restore_", "panel_runtime;DROP ROLE postgres", "panel_runtime_restore_012345ABCDEf", "panel_runtime_restore_012345abcdef_other"} {
		if validRuntimeRole(role) {
			t.Fatal("foreign or ambiguous role accepted")
		}
	}
}
