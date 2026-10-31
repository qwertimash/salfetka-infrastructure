package database_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"salfetka/panel/internal/database"
	"salfetka/panel/internal/database/dbtest"
	"salfetka/panel/migrations"
)

// Upgrade an actual old schema, not a fresh schema with legacy-shaped rows.
func TestSubscriptionSetsUpgradePreservesLegacyDeliveryAndIdentity(t *testing.T) {
	p := dbtest.NewUnmigrated(t)
	ctx := context.Background()
	_, e := p.Exec(ctx, `CREATE TABLE schema_migrations(version integer PRIMARY KEY,name text NOT NULL UNIQUE,checksum text NOT NULL)`)
	if e != nil {
		t.Fatal(e)
	}
	entries, e := fs.ReadDir(migrations.Files, ".")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		var version int
		fmt.Sscanf(entry.Name(), "%03d_", &version)
		if version > 17 {
			continue
		}
		body, e := fs.ReadFile(migrations.Files, entry.Name())
		if e != nil {
			t.Fatal(e)
		}
		if _, e = p.Exec(ctx, string(body)); e != nil {
			t.Fatal(entry.Name(), e)
		}
		hash := sha256.Sum256(body)
		if _, e = p.Exec(ctx, "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)", version, entry.Name(), fmt.Sprintf("%x", hash)); e != nil {
			t.Fatal(e)
		}
	}
	// Synthetic encrypted bytes stand for pre-existing opaque credentials. The
	// migration must not regenerate or normalize any of them, nor delivery IDs.
	_, e = p.Exec(ctx, `
 INSERT INTO access_users(id,name) VALUES('10000000-0000-4000-8000-000000000001','Legacy fixture');
 INSERT INTO access_devices(id,user_id,name,state,public_key) VALUES('20000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','Legacy device','registered',decode(repeat('ab',32),'hex'));
 INSERT INTO access_credentials(id,user_id,device_id,version,state,ciphertext) VALUES('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001',1,'active',decode(repeat('cd',64),'hex'));
 INSERT INTO subscriptions(id,user_id,device_id,revision,next_release,token_hash,token_ciphertext,token_revision) VALUES('40000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001',5,2,decode(repeat('ef',32),'hex'),decode(repeat('12',64),'hex'),1);
 INSERT INTO subscription_releases(id,subscription_id,number,base_revision,access_revision,policy_epoch,credential_id,recipe_ciphertext,artifact_ciphertext,digest,preview,provenance) VALUES('50000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',1,1,1,1,'30000000-0000-4000-8000-000000000001',decode(repeat('34',64),'hex'),decode(repeat('56',64),'hex'),repeat('a',64),'{}','{}');
 INSERT INTO subscription_release_status(release_id,state) VALUES('50000000-0000-4000-8000-000000000001','published');
 UPDATE subscriptions SET active_release='50000000-0000-4000-8000-000000000001';
 `)
	if e != nil {
		t.Fatal(e)
	}
	tables := []string{"access_users", "access_devices", "access_credentials", "subscriptions", "subscription_releases", "subscription_release_status"}
	snapshot := func() [32]byte {
		t.Helper()
		parts := []string{}
		for _, table := range tables {
			var data string
			if e = p.QueryRow(ctx, "SELECT coalesce(jsonb_agg((to_jsonb(t)-'assignment_id'-'assignment_revision') ORDER BY to_jsonb(t)::text),'[]')::text FROM "+table+" t").Scan(&data); e != nil {
				t.Fatal(e)
			}
			parts = append(parts, data)
		}
		return sha256.Sum256([]byte(strings.Join(parts, "\n")))
	}
	before := snapshot()
	if database.Ready(ctx, p) == nil {
		t.Fatal("old schema considered ready for new binary")
	}
	for i := 0; i < 2; i++ {
		if e = database.Migrate(ctx, p); e != nil {
			t.Fatal(e)
		}
		if snapshot() != before {
			t.Fatal("migration changed legacy credentials or delivery")
		}
	}
	if e = database.Ready(ctx, p); e != nil {
		t.Fatal(e)
	}
	// Legacy user/device queries remain unambiguous until P2 switches scopes.
	_, e = p.Exec(ctx, `INSERT INTO subscriptions(id,user_id,device_id) VALUES('40000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','20000000-0000-4000-8000-000000000001')`)
	if e == nil {
		t.Fatal("legacy unique device boundary silently removed")
	}
	var count int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM subscription_sets").Scan(&count); e != nil || count != 0 {
		t.Fatal("migration auto-created sets", e)
	}
}
