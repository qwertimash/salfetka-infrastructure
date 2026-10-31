package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"salfetka/panel/internal/appconfig"
)

func TestNodeAuthorityCreationRetryAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "authority")
	if err := initNodeAuthority([]string{"--file", path}); err != nil {
		t.Fatal(err)
	}
	first, err := appconfig.PrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANEL_NODE_AUTHORITY_FILE", path)
	if _, err := appconfig.LoadNodeAuthority(); err != nil {
		t.Fatal(err)
	}
	if err := initNodeAuthority([]string{"--file", path}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(first, after) {
		t.Fatal("retry rotated the node authority")
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := initNodeAuthority([]string{"--file", link}); err == nil {
		t.Fatal("authority accepted a symlink")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := appconfig.LoadNodeAuthority(); err == nil {
		t.Fatal("authority accepted world-readable private key")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid synthetic bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initNodeAuthority([]string{"--file", path}); err == nil {
		t.Fatal("authority silently replaced invalid existing bundle")
	}
	if _, err := appconfig.LoadNodeAuthority(); err == nil {
		t.Fatal("invalid authority loaded")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initNodeAuthority([]string{"--file", filepath.Join(dir, "other")}); err == nil {
		t.Fatal("authority created in nonprivate directory")
	}
}
