package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/osv"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// fakeDoer returns a canned OSV querybatch response, mirroring the pattern
// already used in internal/datasource/osv/osv_test.go (unexported there, so
// duplicated rather than imported).
type fakeDoer struct{ body string }

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

// A live network round trip (-osv-export then -osv-snapshot) is exactly the
// scenario a real network-restricted sandbox cannot exercise end-to-end —
// which is the whole reason this feature exists. This test proves the round
// trip works using an injected transport, the same way osv_test.go verifies
// QueryBatch without a real network call.
func TestPrefetchAdvisoriesBuildsExportableEntries(t *testing.T) {
	g := graph.New()
	rootID := purl.NewNpm("app", "1.0.0").String()
	g.AddNode(&graph.Node{ID: rootID, Kind: graph.KindPackage, Ecosystem: "npm", Name: "app", Version: "1.0.0"})
	g.MarkRoot(rootID)
	evilID := purl.NewNpm("evil-pkg", "2.0.0").String()
	g.AddNode(&graph.Node{ID: evilID, Kind: graph.KindPackage, Ecosystem: "npm", Name: "evil-pkg", Version: "2.0.0"})
	cleanID := purl.NewNpm("clean-pkg", "3.0.0").String()
	g.AddNode(&graph.Node{ID: cleanID, Kind: graph.KindPackage, Ecosystem: "npm", Name: "clean-pkg", Version: "3.0.0"})

	// prefetchAdvisories queries in SortedNodes order (deterministic, by PURL):
	// "pkg:npm/clean-pkg@..." sorts before "pkg:npm/evil-pkg@...", so the
	// clean result comes first in the response.
	resp := `{"results":[
		{},
		{"vulns":[{"id":"MAL-2026-1","modified":"2026-08-04T00:00:00Z"}]}
	]}`
	dir := t.TempDir()
	cache := datasource.NewCache(filepath.Join(dir, "cache"), 24*time.Hour)
	client := osv.New(cache, false)
	client.HTTP = &fakeDoer{body: resp}

	byNode, entries, err := prefetchAdvisories(g, client)
	if err != nil {
		t.Fatalf("prefetchAdvisories: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if len(byNode) != 2 {
		t.Fatalf("byNode = %d, want 2", len(byNode))
	}

	var evilEntry, cleanEntry *datasource.SnapshotEntry
	for i := range entries {
		switch entries[i].Name {
		case "evil-pkg":
			evilEntry = &entries[i]
		case "clean-pkg":
			cleanEntry = &entries[i]
		}
	}
	if evilEntry == nil || cleanEntry == nil {
		t.Fatalf("missing expected entries: %+v", entries)
	}
	if len(evilEntry.Advisories) != 1 || evilEntry.Advisories[0].ID != "MAL-2026-1" {
		t.Errorf("evil-pkg advisories = %+v, want one MAL-2026-1", evilEntry.Advisories)
	}
	// A genuinely clean, queried coordinate must round-trip as an EMPTY
	// advisories list, not be absent or nil — the whole point is that
	// "checked and clean" must survive the export/import cycle exactly like
	// "checked and flagged" does, or an importer would treat it as unknown.
	if cleanEntry.Advisories == nil || len(cleanEntry.Advisories) != 0 {
		t.Errorf("clean-pkg advisories = %+v, want a non-nil empty slice", cleanEntry.Advisories)
	}

	// Export, then import into a fresh cache, then confirm the imported cache
	// reproduces exactly what the live query saw — the full round trip.
	exportPath := filepath.Join(dir, "export.json")
	if err := datasource.ExportSnapshot(exportPath, entries); err != nil {
		t.Fatalf("ExportSnapshot: %v", err)
	}
	freshCache := datasource.NewCache(filepath.Join(dir, "fresh-cache"), 24*time.Hour)
	n, err := datasource.ImportSnapshot(freshCache, exportPath, time.Now())
	if err != nil {
		t.Fatalf("ImportSnapshot: %v", err)
	}
	if n != 2 {
		t.Fatalf("imported %d entries, want 2", n)
	}
	offlineClient := osv.New(freshCache, true) // -offline
	_, replayed, err := prefetchAdvisories(g, offlineClient)
	if err != nil {
		t.Fatalf("offline replay prefetchAdvisories: %v", err)
	}
	if offlineClient.Stats.Gaps != 0 {
		t.Errorf("offline replay should have zero gaps after import, got %d", offlineClient.Stats.Gaps)
	}
	var replayedEvil *datasource.SnapshotEntry
	for i := range replayed {
		if replayed[i].Name == "evil-pkg" {
			replayedEvil = &replayed[i]
		}
	}
	if replayedEvil == nil || len(replayedEvil.Advisories) != 1 || !replayedEvil.Advisories[0].Malicious {
		t.Errorf("offline replay lost the malicious advisory: %+v", replayed)
	}
}

func TestPrefetchAdvisoriesSkipsExportOnQueryError(t *testing.T) {
	g := graph.New()
	rootID := purl.NewNpm("app", "1.0.0").String()
	g.AddNode(&graph.Node{ID: rootID, Kind: graph.KindPackage, Ecosystem: "npm", Name: "app", Version: "1.0.0"})
	g.MarkRoot(rootID)
	g.AddNode(&graph.Node{ID: purl.NewNpm("dep", "1.0.0").String(), Kind: graph.KindPackage, Ecosystem: "npm", Name: "dep", Version: "1.0.0"})

	dir := t.TempDir()
	cache := datasource.NewCache(filepath.Join(dir, "cache"), 24*time.Hour)
	client := osv.New(cache, false)
	client.HTTP = &erroringDoer{}

	_, _, err := prefetchAdvisories(g, client)
	if err == nil {
		t.Fatal("expected an error from a failing OSV query")
	}
	// This mirrors cmdScan's own gate: exportEntries must never be written to
	// disk when qErr != nil, verified here at the boundary the caller checks.
}

type erroringDoer struct{}

func (*erroringDoer) Do(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

func TestExportIncompatibleWithOfflineAndNoOSV(t *testing.T) {
	dir := t.TempDir()
	exportPath := filepath.Join(dir, "out.json")
	fixture := "../../internal/ecosystem/npm/testdata/emptylock"

	for _, args := range [][]string{
		{"scan", "-osv-export", exportPath, "-offline", "-no-registry", fixture},
		{"scan", "-osv-export", exportPath, "-no-osv", "-no-registry", fixture},
	} {
		code := run(args)
		if code != exitUsage {
			t.Errorf("run(%v) = %d, want exitUsage (%d)", args, code, exitUsage)
		}
		if _, err := os.Stat(exportPath); err == nil {
			t.Errorf("run(%v) should not have written %s", args, exportPath)
		}
	}
}

func TestExportedSnapshotDecodesWithImportSnapshot(t *testing.T) {
	dir := t.TempDir()
	exportPath := filepath.Join(dir, "out.json")

	entries := []datasource.SnapshotEntry{
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0", Advisories: []datasource.Advisory{
			{ID: "CVE-2026-1", Source: "osv"},
		}},
	}
	if err := datasource.ExportSnapshot(exportPath, entries); err != nil {
		t.Fatalf("ExportSnapshot: %v", err)
	}
	raw, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []datasource.SnapshotEntry
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("exported file is not valid SnapshotEntry JSON: %v", err)
	}
	if len(decoded) != 1 || decoded[0].Name != "requests" {
		t.Errorf("decoded = %+v, want one requests entry", decoded)
	}
}
