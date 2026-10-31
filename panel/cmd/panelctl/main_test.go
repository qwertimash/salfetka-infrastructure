package main

import (
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareCreatesPrivateRandomFilesAndRefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "install")
	if e := prepare([]string{"--dir", dir}); e != nil {
		t.Fatal(e)
	}
	first, e := os.ReadFile(filepath.Join(dir, "postgres-password"))
	if e != nil {
		t.Fatal(e)
	}
	runtime, e := os.ReadFile(filepath.Join(dir, "runtime-password"))
	if e != nil {
		t.Fatal(e)
	}
	if len(first) != 44 || len(runtime) != 44 || string(first) == string(runtime) {
		t.Fatal("credentials are not independent high entropy values")
	}
	for _, name := range []string{"postgres-password", "runtime-password", "master-key", "node-authority", "node-signer", "node-signer.pub", "database-runtime-url", "database-migrator-url", "tls.key", "compose.env"} {
		info, e := os.Stat(filepath.Join(dir, name))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe generated permissions")
		}
	}
	if _, e = tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); e != nil {
		t.Fatal("invalid local TLS fixture")
	}
	if e = prepare([]string{"--dir", dir}); e == nil {
		t.Fatal("overwrote installation")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "postgres-password"))
	if string(first) != string(after) {
		t.Fatal("password changed on retry")
	}
}

func TestBootstrapFileSurvivesRetryAndIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	a, e := tokenFile(path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := tokenFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if a.Token != b.Token || !a.ExpiresAt.Equal(b.ExpiresAt) {
		t.Fatal("retry changed token or lifetime")
	}
	if !a.ExpiresAt.After(time.Now()) || a.ExpiresAt.After(time.Now().Add(31*time.Minute)) {
		t.Fatal("bootstrap is unbounded")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe bootstrap permissions")
	}
	before, _ := os.ReadFile(path)
	var v bootstrapFile
	if json.Unmarshal(before, &v) != nil || v.Token == "" {
		t.Fatal("missing token")
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = tokenFile(path); e == nil {
		t.Fatal("unsafe bootstrap file accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("unsafe file overwritten")
	}
}
