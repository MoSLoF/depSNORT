package main

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestClassifyGapManifest(t *testing.T) {
	gaps := map[string]string{
		"Titanis.csproj":  "nuget",
		"app.fsproj":      "nuget",
		"packages.config": "nuget",
		"pom.xml":         "maven",
		"build.gradle":    "gradle",
		"pnpm-lock.yaml":  "pnpm",
		"poetry.lock":     "pypi",
		"Pipfile":         "pypi",
		"Gemfile":         "rubygems",
	}
	for name, wantEco := range gaps {
		if eco, ok := classifyGapManifest(name); !ok || eco != wantEco {
			t.Errorf("classifyGapManifest(%q) = (%q,%v), want (%q,true)", name, eco, ok, wantEco)
		}
	}
	// Supported manifests must NOT be gap manifests: a dir carrying one is claimed
	// by a real adapter, and a dep-less one is legitimately empty, not a gap.
	for _, name := range []string{"package.json", "requirements.txt", "pyproject.toml", "composer.json", "go.mod", "Cargo.lock", "packages.lock.json", "README.md"} {
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
