package builder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/releases"
	"salfetka/panel/internal/secrets"
	"sync"
	"testing"
)

func TestSavedDraftCASReplayEncryptionAndPagination(t *testing.T) {
	p := dbtest.New(t)
	v, _ := secrets.New(bytes.Repeat([]byte{29}, 32))
	s := New(p, v)
	actor, _ := database.NewID()
	ctx := context.Background()
	run := func(m Mutation) (Draft, bool, error) {
		tx, e := p.Begin(ctx)
		if e != nil {
			return Draft{}, false, e
		}
		defer database.Rollback(tx)
		d, r, e := s.SaveTx(ctx, tx, m)
		if e == nil {
			e = tx.Commit(ctx)
		}
		return d, r, e
	}
	doc := Document{Title: "Private blueprint", Recipe: releases.Recipe{MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1, Locations: []compiler.Location{}, Routing: map[string]compiler.PolicyChoice{}}}}
	m := Mutation{Actor: actor, Key: "builder-create-test-0001", Document: doc}
	d, replay, e := run(m)
	if e != nil || replay || d.Revision != 1 {
		t.Fatal("create", e)
	}
	m.ID = d.ID
	m.Revision = 1
	m.Key = "builder-save-test-0001"
	m.Document.Title = "Changed draft"
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			copy := m
			copy.Key = fmt.Sprintf("builder-concurrent-%04d", n)
			_, _, e := run(copy)
			out <- e
		}(n)
	}
	wg.Wait()
	close(out)
	passed, conflicts := 0, 0
	for e := range out {
		if e == nil {
			passed++
		} else if e == ErrConflict {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if passed != 1 || conflicts != 1 {
		t.Fatal("lost concurrent edit")
	}
	original := Mutation{Actor: actor, Key: "builder-create-test-0001", Document: doc}
	recovered, replay, e := run(original)
	if e != nil || !replay || recovered.Revision != 1 || recovered.Document.Title != "Private blueprint" {
		t.Fatal("lost ACK recovery", e)
	}
	original.Document.Title = "different payload"
	if _, _, e = run(original); e != ErrConflict {
		t.Fatal("idempotency conflict", e)
	}
	var ciphertext []byte
	if e = p.QueryRow(ctx, "SELECT body_ciphertext FROM builder_versions WHERE draft_id=$1 AND revision=1", d.ID).Scan(&ciphertext); e != nil || bytes.Contains(ciphertext, []byte(doc.Title)) {
		t.Fatal("plaintext stored", e)
	}
	tx, _ := p.Begin(ctx)
	defer database.Rollback(tx)
	page, e := s.ListTx(ctx, tx, "")
	if e != nil || len(page.Items) != 1 || page.Items[0].Revision != 2 {
		t.Fatal("list", e)
	}
	if _, e = tx.Exec(ctx, "UPDATE builder_versions SET body_ciphertext=$2 WHERE draft_id=$1", d.ID, []byte("corrupt")); e == nil {
		t.Fatal("immutable snapshot changed")
	}
}
func TestDraftCannotInjectEngineSettingsOrServerBindings(t *testing.T) {
	doc := Document{Title: "Draft", Recipe: releases.Recipe{MaxVersion: 2, Engines: []string{"xray"}, Blueprint: &compiler.Blueprint{Version: 1}}}
	if !valid(doc) {
		t.Fatal("incomplete draft must be saveable")
	}
	doc.Recipe.NodeBindings = map[string]string{"fake": "binding"}
	if valid(doc) {
		t.Fatal("binding injection")
	}
	doc.Recipe.NodeBindings = nil
	doc.Recipe.Network = json.RawMessage(`{}`)
	if valid(doc) {
		t.Fatal("ambiguous network")
	}
}
