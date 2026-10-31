package trafficexport

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"salfetka/panel/internal/nodewire"
)

const nodeID = "00000000-0000-4000-8000-000000000001"
const grantID = "00000000-0000-4000-8000-000000000002"

func fixture() storedReport {
	epoch := strings.Repeat("a", 32)
	zero, down := int64(0), int64(123)
	now := time.Now().UTC()
	u := nodewire.VPNUsage{GrantID: grantID, InstanceEpoch: epoch, Generation: 1, Active: true, Uplink: &zero, Downlink: &down}
	r := nodewire.VPNReport{Receipt: nodewire.VPNReceipt{SchemaVersion: 1, NodeID: nodeID,
		InstallationID: grantID, Generation: 1, PolicySHA256: strings.Repeat("b", 64),
		Status: "applied", CompletedAt: now, Usage: []nodewire.VPNUsage{u}},
		EngineEpoch: epoch, Sequence: 1, ObservedAt: now, Usage: []nodewire.VPNUsage{u}}
	raw, _ := json.Marshal(r)
	hash := sha256.Sum256(raw)
	return storedReport{body: string(raw), hash: hash[:], node: nodeID, epoch: epoch,
		installation: grantID, state: "active", sequence: 1, generation: 1, desired: 1,
		currentEpoch: &epoch, enabled: true}
}

func TestDecodeIntegrityAndCurrentIdentity(t *testing.T) {
	r, err := decode(fixture())
	if err != nil || *r.Usage[0].Downlink != 123 {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*storedReport)
		want   error
	}{
		{"hash", func(r *storedReport) { r.hash = []byte("bad") }, ErrIntegrity},
		{"node", func(r *storedReport) { r.node = grantID }, ErrIntegrity},
		{"sequence", func(r *storedReport) { r.sequence++ }, ErrIntegrity},
		{"installation", func(r *storedReport) { r.installation = nodeID }, ErrIntegrity},
		{"epoch", func(r *storedReport) { r.currentEpoch = nil }, ErrNotCurrent},
		{"generation", func(r *storedReport) { r.desired++ }, ErrNotCurrent},
		{"revoked", func(r *storedReport) { r.state = "revoked" }, ErrNotCurrent},
		{"disabled", func(r *storedReport) { r.enabled = false }, ErrNotCurrent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := fixture()
			c.change(&v)
			if _, e := decode(v); !errors.Is(e, c.want) {
				t.Fatal(e)
			}
		})
	}
}

func TestDecodeUnknownSecretFieldRejectedAndNullPreserved(t *testing.T) {
	v := fixture()
	v.body = strings.Replace(v.body, `"downlink":123`, `"downlink":null`, -1)
	h := sha256.Sum256([]byte(v.body))
	v.hash = h[:]
	r, e := decode(v)
	if e != nil || r.Usage[0].Downlink != nil {
		t.Fatal("missing counter changed", e)
	}
	v.body = strings.Replace(v.body, `"sequence":1`, `"sequence":1,"credential":"PRIVATE_SENTINEL"`, 1)
	h = sha256.Sum256([]byte(v.body))
	v.hash = h[:]
	if _, e = decode(v); e != ErrIntegrity || strings.Contains(e.Error(), "PRIVATE_SENTINEL") {
		t.Fatal("private input surfaced")
	}
}

func TestOldReportKeepsMeasurementTimeAndSeparateCounters(t *testing.T) {
	v := fixture()
	r, e := decode(v)
	if e != nil {
		t.Fatal(e)
	}
	r.ObservedAt = time.Now().UTC().Add(-time.Hour)
	r.Receipt.CompletedAt = r.ObservedAt
	up := int64(1_000_000_000_000)
	r.Usage[0].Uplink = &up
	raw, _ := json.Marshal(r)
	v.body = string(raw)
	h := sha256.Sum256(raw)
	v.hash = h[:]
	out, e := decode(v)
	if e != nil || !out.ObservedAt.Equal(r.ObservedAt) || *out.Usage[0].Downlink != 123 || *out.Usage[0].Uplink != up {
		t.Fatal("stale report was refreshed or directions mixed", e)
	}
}

func TestNodeAllowlistRequiredUniqueAndBounded(t *testing.T) {
	for _, ids := range [][]string{nil, {}, {nodeID, nodeID}, {"all"}, make([]string, 101)} {
		if ValidNodes(ids) {
			t.Fatal("invalid allowlist accepted")
		}
	}
	if !ValidNodes([]string{nodeID}) {
		t.Fatal("valid allowlist rejected")
	}
}

func TestAtomicPublicationLockPermissionsAndCleanup(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	p, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if other, e := Open(dir); e != ErrBusy {
		if other != nil {
			other.Close()
		}
		t.Fatal("overlapping exporter not rejected", e)
	}
	for _, value := range []string{"first", "second"} {
		if e = p.Write([]byte(value)); e != nil {
			t.Fatal(e)
		}
		raw, e := os.ReadFile(filepath.Join(dir, SnapshotName))
		if e != nil || string(raw) != value {
			t.Fatal(e)
		}
	}
	st, _ := os.Stat(filepath.Join(dir, SnapshotName))
	if st.Mode().Perm() != 0600 {
		t.Fatal("snapshot not private")
	}
	if e = p.Write(make([]byte, MaxBytes+1)); e != ErrFile {
		t.Fatal("oversize accepted", e)
	}
	previous, e := os.ReadFile(filepath.Join(dir, SnapshotName))
	if e != nil || string(previous) != "second" {
		t.Fatal("failed publication lost previous snapshot")
	}
	names, _ := os.ReadDir(dir)
	if len(names) != 2 {
		t.Fatal("temporary file left behind")
	}
	p.Close()
	if p.Write([]byte("after close")) != ErrFile {
		t.Fatal("write after close")
	}
	next, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
}

func TestUnsafePublicationTargetsPreserved(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "public", "directory"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			other := filepath.Join(t.TempDir(), "original")
			os.WriteFile(other, []byte("keep"), 0600)
			target := filepath.Join(dir, SnapshotName)
			var e error
			switch mode {
			case "symlink":
				e = os.Symlink(other, target)
			case "hardlink":
				e = os.Link(other, target)
			case "public":
				e = os.WriteFile(target, []byte("keep"), 0644)
				if e == nil {
					e = os.Chmod(target, 0644)
				}
			case "directory":
				e = os.Mkdir(target, 0700)
			}
			if e != nil {
				t.Fatal(e)
			}
			p, e := Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			if e = p.Write([]byte("replace")); e != ErrFile {
				t.Fatal("unsafe target replaced", e)
			}
			raw, _ := os.ReadFile(other)
			if string(raw) != "keep" {
				t.Fatal("original changed")
			}
		})
	}
}

func TestUnsafeDirectoryAndLockRejected(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0755)
	if p, e := Open(dir); e != ErrFile {
		if p != nil {
			p.Close()
		}
		t.Fatal("public directory accepted")
	}
	os.Chmod(dir, 0700)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(dir, link)
	if p, e := Open(link); e != ErrFile {
		if p != nil {
			p.Close()
		}
		t.Fatal("directory symlink accepted")
	}
	os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, ".export.lock"))
	if p, e := Open(dir); e != ErrFile {
		if p != nil {
			p.Close()
		}
		t.Fatal("lock symlink accepted")
	}
}
