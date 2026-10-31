package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/secrets"
)

const fixtureURI = "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?security=tls&type=tcp#private-title"

func fixture(t *testing.T) (*Store, string) {
	p := dbtest.New(t)
	v, _ := secrets.New(bytes.Repeat([]byte{9}, 32))
	actor, _ := database.NewID()
	return New(p, v), actor
}
func transaction(s *Store, fn func(pgx.Tx) error) error {
	ctx := context.Background()
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer database.Rollback(tx)
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func draft(t *testing.T, s *Store, actor, kind, input string) Draft {
	t.Helper()
	p, e := s.Prepare(context.Background(), Input{Name: "Synthetic source", Kind: kind, Input: input})
	if e != nil {
		t.Fatal(e)
	}
	var d Draft
	e = transaction(s, func(tx pgx.Tx) error { var e error; d, e = s.DraftTx(context.Background(), tx, actor, p); return e })
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func mutate(s *Store, m Mutation) (Source, bool, error) {
	var n Source
	var replay bool
	e := transaction(s, func(tx pgx.Tx) error { var e error; n, replay, e = s.MutateTx(context.Background(), tx, m); return e })
	return n, replay, e
}
func get(t *testing.T, s *Store, id string) Source {
	t.Helper()
	var n Source
	e := transaction(s, func(tx pgx.Tx) error { var e error; n, e = s.GetTx(context.Background(), tx, id); return e })
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func TestSourceDraftAtomicCreationReplayEncryptionAndAudit(t *testing.T) {
	s, actor := fixture(t)
	ctx := context.Background()
	d := draft(t, s, actor, "upload", fixtureURI)
	m := Mutation{Actor: actor, Key: "source-create-0001", Operation: "create", DraftID: d.ID}
	first, repeat, e := mutate(s, m)
	if e != nil || repeat || first.Current == nil {
		t.Fatal("create", e)
	}
	second, repeat, e := mutate(s, m)
	if e != nil || !repeat || second.ID != first.ID {
		t.Fatal("lost ACK retry", e)
	}
	m.DraftID, _ = database.NewID()
	if _, _, e = mutate(s, m); !errors.Is(e, ErrConflict) {
		t.Fatal("key collision", e)
	}
	m.DraftID = d.ID
	m.Key = "source-create-0002"
	if _, _, e = mutate(s, m); !errors.Is(e, ErrConflict) {
		t.Fatal("draft reused", e)
	}
	var cipher, preview []byte
	var count int
	if e = s.Pool.QueryRow(ctx, "SELECT body_ciphertext,preview FROM catalog_versions WHERE id=$1", first.Current.ID).Scan(&cipher, &preview); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(cipher, []byte("11111111")) || bytes.Contains(preview, []byte("private-title")) {
		t.Fatal("plaintext source")
	}
	doc, e := s.document(cipher, "version:"+first.ID+":"+first.Current.ID)
	if e != nil || string(doc.Raw) != fixtureURI {
		t.Fatal("lossless original", e)
	}
	if _, e = s.document(cipher, "version:other:"+first.Current.ID); e == nil {
		t.Fatal("AAD moved")
	}
	for _, sql := range []string{"UPDATE catalog_versions SET digest=digest", "DELETE FROM catalog_versions", "TRUNCATE catalog_mutations"} {
		if _, e = s.Pool.Exec(ctx, sql); e == nil {
			t.Fatal("immutable record changed")
		}
	}
	s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='source.create'").Scan(&count)
	if count != 1 {
		t.Fatal("audit duplicate")
	}
	s.Pool.QueryRow(ctx, "SELECT count(*) FROM nodes_vpn_policies").Scan(&count)
	if count != 0 {
		t.Fatal("import published VPN")
	}
}
func TestDraftOwnerExpiryAndConcurrentCreation(t *testing.T) {
	s, actor := fixture(t)
	d := draft(t, s, actor, "upload", fixtureURI)
	other, _ := database.NewID()
	m := Mutation{Actor: other, Key: "source-owner-0001", Operation: "create", DraftID: d.ID}
	if _, _, e := mutate(s, m); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross owner draft")
	}
	s.Pool.Exec(context.Background(), "UPDATE catalog_drafts SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", d.ID)
	m.Actor = actor
	if _, _, e := mutate(s, m); !errors.Is(e, ErrExpired) {
		t.Fatal("expired preview")
	}
	d = draft(t, s, actor, "upload", fixtureURI)
	m.DraftID = d.ID
	m.Key = "source-race-00001"
	var wg sync.WaitGroup
	ids := make(chan string, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); n, _, e := mutate(s, m); ids <- n.ID; errs <- e }()
	}
	wg.Wait()
	if e := <-errs; e != nil {
		t.Fatal(e)
	}
	if e := <-errs; e != nil {
		t.Fatal(e)
	}
	if <-ids != <-ids {
		t.Fatal("concurrent duplicate")
	}
}
func TestRefreshRetainsCurrentOnFailurePartialAndExpiryAndRequiresReview(t *testing.T) {
	s, actor := fixture(t)
	ctx := context.Background()
	expiry := time.Now().Add(time.Hour)
	raw := fixtureURI + "\n" + fixtureURI
	s.fetch = func(context.Context, string) (importer.FetchResult, error) {
		return importer.FetchResult{Data: []byte(raw), ExpiresAt: &expiry}, nil
	}
	d := draft(t, s, actor, "url", "https://example.com/private-subscription-token")
	n, _, e := mutate(s, Mutation{Actor: actor, Key: "source-refresh-create", Operation: "create", DraftID: d.ID})
	if e != nil {
		t.Fatal(e)
	}
	initial := n.Current.ID
	due := func() {
		t.Helper()
		if _, e := s.Pool.Exec(ctx, "UPDATE catalog_sources SET next_fetch_at=clock_timestamp()-interval '1 second' WHERE id=$1", n.ID); e != nil {
			t.Fatal(e)
		}
	}
	refresh := func() {
		t.Helper()
		due()
		worked, e := s.RefreshOne(ctx)
		if e != nil || !worked {
			t.Fatal("refresh", e)
		}
		n = get(t, s, n.ID)
	}
	s.fetch = func(context.Context, string) (importer.FetchResult, error) {
		return importer.FetchResult{}, errors.New("private upstream response")
	}
	refresh()
	if n.Current.ID != initial || n.ErrorCode == nil || *n.ErrorCode != "source_refresh_failed" || n.NextFetchAt == nil {
		t.Fatal("last good lost")
	}
	s.fetch = func(context.Context, string) (importer.FetchResult, error) {
		return importer.FetchResult{Data: []byte(fixtureURI), ExpiresAt: &expiry}, nil
	}
	refresh()
	if n.Current.ID != initial || n.Candidate == nil || len(n.Candidate.Preview.Profiles) != 1 || len(n.Current.Preview.Profiles) != 2 || n.ErrorCode != nil {
		t.Fatal("partial response silently replaced good version")
	}
	candidate := n.Candidate.ID
	refresh()
	if n.Candidate.ID != candidate {
		t.Fatal("identical refresh created a revision")
	}
	stale := Mutation{Actor: actor, Key: "source-stale-00001", Operation: "accept", ID: n.ID, Revision: n.Revision - 1, VersionID: candidate}
	if _, _, e = mutate(s, stale); !errors.Is(e, ErrRevision) {
		t.Fatal("CAS not enforced")
	}
	stale.Revision = n.Revision
	n, _, e = mutate(s, stale)
	if e != nil || n.Current.ID != candidate || n.Candidate != nil {
		t.Fatal("explicit review failed", e)
	}
	expiry = time.Now().Add(-time.Minute)
	refresh()
	if n.Current.ID != candidate || n.ErrorCode == nil || *n.ErrorCode != "source_expired" {
		t.Fatal("expiry extended or good removed")
	}
	safe, _ := json.Marshal(n)
	for _, secret := range []string{"private-subscription-token", "11111111", "private-title", "private upstream"} {
		if strings.Contains(string(safe), secret) {
			t.Fatal("secret in list")
		}
	}
}
func TestStaleRefreshLeaseCannotReplaceAfterPause(t *testing.T) {
	s, actor := fixture(t)
	ctx := context.Background()
	s.fetch = func(context.Context, string) (importer.FetchResult, error) {
		return importer.FetchResult{Data: []byte(fixtureURI)}, nil
	}
	d := draft(t, s, actor, "url", "https://example.com/source")
	n, _, e := mutate(s, Mutation{Actor: actor, Key: "source-lease-create", Operation: "create", DraftID: d.ID})
	if e != nil {
		t.Fatal(e)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	s.fetch = func(context.Context, string) (importer.FetchResult, error) {
		close(started)
		<-release
		return importer.FetchResult{Data: []byte(fixtureURI + "\n" + fixtureURI)}, nil
	}
	s.Pool.Exec(ctx, "UPDATE catalog_sources SET next_fetch_at=clock_timestamp() WHERE id=$1", n.ID)
	done := make(chan error)
	go func() { _, e := s.RefreshOne(ctx); done <- e }()
	<-started
	if worked, e := s.RefreshOne(ctx); e != nil || worked {
		t.Fatal("duplicate worker claimed active lease")
	}
	n, _, e = mutate(s, Mutation{Actor: actor, Key: "source-lease-pause", Operation: "pause", ID: n.ID, Revision: n.Revision, Paused: true})
	if e != nil {
		t.Fatal(e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	n = get(t, s, n.ID)
	if !n.Paused || n.Candidate != nil || len(n.Current.Preview.Profiles) != 1 {
		t.Fatal("stale fetch committed after pause")
	}
}
