package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"salfetka/panel/internal/appconfig"
)

func TestNodeSignerCreateRetryPartialRecoveryAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	private, public := filepath.Join(dir, "signer"), filepath.Join(dir, "signer.pub")
	args := []string{"--file", private, "--public-file", public}
	if err := initNodeSigner(args); err != nil {
		t.Fatal(err)
	}
	first, err := appconfig.PrivateFile(private)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANEL_NODE_SIGNER_FILE", private)
	signer, err := appconfig.LoadNodeSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := initNodeSigner(args); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(public); err != nil {
		t.Fatal(err)
	}
	if err := initNodeSigner(args); err != nil {
		t.Fatal("missing public export recovery", err)
	}
	after, _ := appconfig.PrivateFile(private)
	pub, _ := appconfig.PrivateFile(public)
	if !bytes.Equal(first, after) || !bytes.Equal(pub, signer.PublicPEM()) {
		t.Fatal("partial retry rotated identity")
	}
	if err := os.WriteFile(public, []byte("invalid public fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initNodeSigner(args); err == nil {
		t.Fatal("silently repaired mismatched public export")
	}
	if err := os.Remove(public); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, public); err != nil {
		t.Fatal(err)
	}
	if err := initNodeSigner(args); err == nil {
		t.Fatal("accepted symlink export")
	}
	if err := os.Remove(public); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := appconfig.LoadNodeSigner(); err == nil {
		t.Fatal("world readable private signer loaded")
	}
	if err := initNodeSigner(args); err == nil {
		t.Fatal("world readable private signer accepted")
	}
	if err := os.Chmod(private, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(private, []byte("corrupt private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initNodeSigner(args); err == nil {
		t.Fatal("silently regenerated corrupt signer")
	}
	if err := os.Remove(private); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, pub, 0600); err != nil {
		t.Fatal(err)
	}
	if err := initNodeSigner(args); err == nil {
		t.Fatal("replaced private identity while public export exists")
	}
	if _, err := os.Stat(private); !os.IsNotExist(err) {
		t.Fatal("unexpected private key creation")
	}
}
