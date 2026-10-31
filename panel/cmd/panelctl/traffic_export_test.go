package main

import (
	"os"
	"path/filepath"
	"testing"

	"salfetka/panel/internal/trafficexport"
)

func TestTrafficExportRequiresExplicitValidSelectionBeforeDatabase(t *testing.T) {
	t.Setenv("PANEL_DATABASE_URL_FILE", filepath.Join(t.TempDir(), "absent"))
	for _, args := range [][]string{{"export-traffic"}, {"export-traffic", "--all"}} {
		if e := run(args); e != trafficexport.ErrInvalid {
			t.Fatal(e)
		}
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	file := filepath.Join(dir, "nodes.json")
	os.WriteFile(file, []byte(`["00000000-0000-4000-8000-000000000001"]`), 0600)
	if e := run([]string{"export-traffic", "--nodes-file", file, "--output-dir", dir}); e != trafficexport.ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, trafficexport.SnapshotName)); !os.IsNotExist(e) {
		t.Fatal("failed export published output")
	}
	os.WriteFile(file, []byte(`[]`), 0600)
	if e := run([]string{"export-traffic", "--nodes-file", file, "--output-dir", dir}); e != trafficexport.ErrInvalid {
		t.Fatal(e)
	}
}
