package secrets

import (
	"bytes"
	"context"
	"salfetka/panel/internal/database/dbtest"
	"sync"
	"testing"
	"time"
)

func TestInstallationBindingConcurrentStartupWrongKeyAndRestart(t *testing.T) {
	p := dbtest.NewUnmigrated(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := p.Exec(ctx, "CREATE TABLE access_key_state(singleton boolean PRIMARY KEY CHECK(singleton),encrypted_check bytea NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	v, _ := New(bytes.Repeat([]byte{2}, 32))
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- BindInstallation(ctx, p, v) }()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent startup failed", err)
		}
	}
	var count int
	var original []byte
	if p.QueryRow(ctx, "SELECT count(*) FROM access_key_state").Scan(&count) != nil || count != 1 {
		t.Fatal("key binding duplicated")
	}
	if p.QueryRow(ctx, "SELECT encrypted_check FROM access_key_state").Scan(&original) != nil {
		t.Fatal("key check missing")
	}
	wrong, _ := New(bytes.Repeat([]byte{3}, 32))
	if err := BindInstallation(ctx, p, wrong); err == nil {
		t.Fatal("wrong installation key accepted")
	}
	var unchanged []byte
	p.QueryRow(ctx, "SELECT encrypted_check FROM access_key_state").Scan(&unchanged)
	if !bytes.Equal(original, unchanged) {
		t.Fatal("wrong key altered binding")
	}
	restarted, _ := New(bytes.Repeat([]byte{2}, 32))
	if err := BindInstallation(ctx, p, restarted); err != nil {
		t.Fatal("restart rejected correct key")
	}
	if _, err := p.Exec(ctx, "UPDATE access_key_state SET encrypted_check=$1", []byte("corrupt synthetic value")); err != nil {
		t.Fatal(err)
	}
	if err := BindInstallation(ctx, p, restarted); err == nil {
		t.Fatal("corrupt binding silently recreated")
	}
}
