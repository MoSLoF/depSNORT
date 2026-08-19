package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The walk itself is tested at its seam (internal/ecosystem/pypi/walk_test.go)
// with an injected registry fake. These tests cover the CLI WIRING, which that
// one cannot: that -expand is on by default, that -no-expand and -no-registry
// each suppress it, and that a run over a real project stays hermetic — offline,
// so no network is touched, and expansion discloses its inability to fetch as a
// degraded data source rather than a silent all-clear.
func dataSources(t *testing.T, reportPath string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		DataSources []struct {
			Name string `json:"name"`
		} `json:"data_sources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range doc.DataSources {
		got[d.Name] = true
	}
	return got
}

func scanPyPI(t *testing.T, extraArgs ...string) map[string]bool {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	// -offline keeps it hermetic: the walk runs but every fetch misses, which
	// is enough to prove the STAGE ran (it registers its data source) without a
	// network.
	args := append([]string{"scan", "-no-osv", "-offline", "-o", out},
		append(extraArgs, "../../internal/ecosystem/pypi/testdata/pipfreeze/requirements.txt")...)
	run(args)
	return dataSources(t, out)
}

func TestExpansionIsOnByDefault(t *testing.T) {
	if !scanPyPI(t)["expand"] {
		t.Error("expansion did not run by default — -expand should default true")
	}
}

func TestNoExpandSuppressesTheStage(t *testing.T) {
	if scanPyPI(t, "-no-expand")["expand"] {
		t.Error("-no-expand did not suppress the expansion stage")
	}
}

func TestExpandFalseSuppressesTheStage(t *testing.T) {
	if scanPyPI(t, "-expand=false")["expand"] {
		t.Error("-expand=false did not suppress the expansion stage")
	}
}

// -no-registry means nothing was fetched at all, so the walk cannot run: it
// would have no declarations to read. It must not register a data source that
// implies it looked.
func TestNoRegistrySuppressesExpansion(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	run([]string{"scan", "-no-osv", "-no-registry", "-o", out,
		"../../internal/ecosystem/pypi/testdata/pipfreeze/requirements.txt"})
	if dataSources(t, out)["expand"] {
		t.Error("expansion ran with -no-registry, but nothing was fetched to expand from")
	}
}
