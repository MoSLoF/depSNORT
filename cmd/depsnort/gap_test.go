package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestClassifyGapManifest(t *testing.T) {
	gaps := map[string]string{
		"Titanis.csproj": "nuget",
		"app.fsproj":     "nuget",
		"pom.xml":        "maven",
		"build.gradle":   "gradle",
		"pnpm-lock.yaml": "pnpm",
		"poetry.lock":    "pypi",
		"Pipfile":        "pypi",
		"Gemfile":        "rubygems",
	}
	for name, wantEco := range gaps {
		if eco, ok := classifyGapManifest(name); !ok || eco != wantEco {
			t.Errorf("classifyGapManifest(%q) = (%q,%v), want (%q,true)", name, eco, ok, wantEco)
		}
	}
	// Supported manifests must NOT be gap manifests: a dir carrying one is claimed
	// by a real adapter, and a dep-less one is legitimately empty, not a gap.
	for _, name := range []string{"package.json", "requirements.txt", "pyproject.toml", "composer.json", "go.mod", "Cargo.lock", "packages.lock.json", "packages.config", "README.md"} {
		if _, ok := classifyGapManifest(name); ok {
			t.Errorf("classifyGapManifest(%q) should be false (supported or non-manifest)", name)
		}
	}
}

func TestRecognizedGapManifestsInDir(t *testing.T) {
	dir := t.TempDir()
	writeGapFile(t, filepath.Join(dir, "Titanis.csproj"), "<Project/>")
	writeGapFile(t, filepath.Join(dir, "README.md"), "# hi")

	got := recognizedGapManifests(dir)
	if len(got) != 1 || got[0].File != "Titanis.csproj" || got[0].Ecosystem != "nuget" {
		t.Fatalf("recognizedGapManifests = %+v, want one Titanis.csproj (nuget)", got)
	}

	// A directory with only a supported manifest yields no gap (it is claimed, or
	// legitimately empty).
	clean := t.TempDir()
	writeGapFile(t, filepath.Join(clean, "package.json"), `{"name":"x"}`)
	if g := recognizedGapManifests(clean); len(g) != 0 {
		t.Errorf("a supported manifest must not be a gap: %+v", g)
	}
}

// The gap adapter's root discloses the unread manifest as incomplete coverage,
// so a recognized-but-unresolved project never reads as a clean pass.
func TestGapAdapterDisclosesIncompleteCoverage(t *testing.T) {
	a := gapAdapter{manifests: []unreadManifest{{File: "Titanis.csproj", Ecosystem: "nuget"}}}
	g, err := a.Resolve("/repo/Titanis")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want one synthetic root", g.Roots)
	}
	cov := g.Coverage()
	if !cov.Incomplete() {
		t.Error("a recognized-but-unresolved manifest must degrade coverage")
	}
	if cov.Unresolved != 1 {
		t.Errorf("Unresolved = %d, want 1", cov.Unresolved)
	}
	root := g.Get(g.Roots[0])
	if root.Attr[graph.AttrUnresolved] == "" {
		t.Error("the unread manifest must be disclosed on the root")
	}
}

func TestDiscoverManifestGapsSkipsClaimed(t *testing.T) {
	root := t.TempDir()
	// A claimed dir (already has a real project) and an unclaimed one with a gap.
	claimedDir := filepath.Join(root, "claimed")
	gapDir := filepath.Join(root, "svc")
	if err := os.MkdirAll(claimedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(gapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeGapFile(t, filepath.Join(claimedDir, "pom.xml"), "<project/>")
	writeGapFile(t, filepath.Join(gapDir, "Svc.csproj"), "<Project/>")

	claimed := map[string]bool{filepath.Clean(claimedDir): true}
	got := discoverManifestGaps(root, claimed)
	if len(got) != 1 || filepath.Clean(got[0].Path) != filepath.Clean(gapDir) {
		t.Fatalf("discoverManifestGaps = %+v, want only the unclaimed svc dir", got)
	}
}

func writeGapFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// OPU-12: a default (non-recursive) scan must disclose projects in
// subdirectories it did not reach, rather than silently under-covering.
func TestDiscoveryGapsSubdirProjects(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "svcA"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "svcB"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeGapFile(t, filepath.Join(root, "svcA", "requirements.txt"), "flask==2.0.1\n")
	writeGapFile(t, filepath.Join(root, "svcB", "go.mod"), "module x\ngo 1.21\n")

	reg := adapterRegistry(true)
	// Root itself is not a project (nothing scanned), so both subdir projects
	// must be disclosed.
	notes := discoveryCoverageGaps(root, nil, reg, false)
	if len(notes) != 2 {
		t.Fatalf("notes = %v, want 2 subdir-project disclosures", notes)
	}
	joined := strings.Join(notes, "|")
	if !strings.Contains(joined, "additional-project") || !strings.Contains(joined, "-recursive") {
		t.Errorf("subdir disclosure should name additional projects and recommend -recursive: %v", notes)
	}
}

// A same-directory polyglot root drops all-but-one ecosystem; the dropped ones
// must be disclosed in BOTH default and recursive mode.
func TestDiscoveryGapsSameDirPolyglot(t *testing.T) {
	dir := t.TempDir()
	writeGapFile(t, filepath.Join(dir, "package-lock.json"), `{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"}}}`)
	writeGapFile(t, filepath.Join(dir, "requirements.txt"), "flask==2.0.1\n")
	writeGapFile(t, filepath.Join(dir, "go.mod"), "module x\ngo 1.21\n")

	reg := adapterRegistry(true)
	adapter, err := reg.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	scanned := []discovered{{Path: dir, Adapter: adapter}}
	for _, recursive := range []bool{false, true} {
		notes := discoveryCoverageGaps(dir, scanned, reg, recursive)
		var dropped int
		for _, n := range notes {
			if strings.Contains(n, "unscanned-ecosystem") {
				dropped++
			}
		}
		if dropped != 2 {
			t.Errorf("recursive=%v: dropped-ecosystem disclosures = %d, want 2 (the two non-winning ecosystems)", recursive, dropped)
		}
	}
}

// A genuine single-project directory with no siblings and no subdir projects
// must produce no disclosure — no false alarm.
func TestDiscoveryGapsSingleProjectQuiet(t *testing.T) {
	dir := t.TempDir()
	writeGapFile(t, filepath.Join(dir, "package-lock.json"), `{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"}}}`)

	reg := adapterRegistry(true)
	adapter, _ := reg.Detect(dir)
	notes := discoveryCoverageGaps(dir, []discovered{{Path: dir, Adapter: adapter}}, reg, false)
	if len(notes) != 0 {
		t.Errorf("a lone single-project directory must produce no disclosure, got %v", notes)
	}
}

// The note adapter's synthetic root discloses its tokens as incomplete coverage.
func TestNoteAdapterDisclosesIncomplete(t *testing.T) {
	g, err := noteAdapter{tokens: []string{"<additional-project: pypi in ./svc>"}}.Resolve("/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !g.Coverage().Incomplete() {
		t.Error("a discovery note must degrade coverage")
	}
}
