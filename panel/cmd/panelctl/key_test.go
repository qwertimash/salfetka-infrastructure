package main

import (
	"os"
	"path/filepath"
	"salfetka/panel/internal/appconfig"
	"testing"
)

func TestMasterKeyCreationIsPrivateAndNeverRotatesOnRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master-key")
	if e := initKey([]string{"--file", path}); e != nil {
		t.Fatal(e)
	}
	a, _ := os.ReadFile(path)
	if len(a) != 44 {
		t.Fatal("wrong encoded key length")
	}
	if e := initKey([]string{"--file", path}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if string(a) != string(b) {
		t.Fatal("key changed on retry")
	}
	t.Setenv("PANEL_MASTER_KEY_FILE", path)
	if _, e := appconfig.LoadVault(); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if e := initKey([]string{"--file", path}); e == nil {
		t.Fatal("unsafe key accepted")
	}
	if _, e := appconfig.LoadVault(); e == nil {
		t.Fatal("unsafe key loaded")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("invalid synthetic value"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := initKey([]string{"--file", path}); e == nil {
		t.Fatal("corrupt key overwritten")
	}
	if _, e := appconfig.LoadVault(); e == nil {
		t.Fatal("corrupt key accepted")
	}
}
