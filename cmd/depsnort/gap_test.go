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
		"Titanis.csproj":     "nuget",
		"app.fsproj":         "nuget",
		"pom.xml":            "maven",
		"build.gradle":       "gradle",
		"pnpm-lock.yaml":     "pnpm",
		"poetry.lock":        "pypi",
		"Pipfile":            "pypi",
		"paket.dependencies": "nuget",
		// OPU-18 Tier 1 — dedicated per-project extensions.
		"mygem.gemspec": "rubygems",
		"MyPod.podspec": "cocoapods",
		"App.vcxproj":   "nuget",
		"myproj.cabal":  "hackage",
		"mypkg.nimble":  "nim",
		"build.sbt":     "sbt",
		// OPU-18 Tier 2 — non-.lock locks + general-ext manifests (name-table only).
		"gradle.lockfile":          "gradle",
		"bun.lockb":                "npm",
		".terraform.lock.hcl":      "terraform",
		"mix.exs":                  "elixir",
		"Directory.Packages.props": "nuget",
		"pubspec.yaml":             "dart",
		"Podfile":                  "cocoapods",
		"Package.swift":            "swift",
		// OPU-18 Tier 3 — .lock files promoted out of "unknown" to the real tool.
		"mix.lock":     "elixir",
		"Podfile.lock": "cocoapods",
		"pubspec.lock": "dart",
		"flake.lock":   "nix",
		"conan.lock":   "conan",
		"deno.lock":    "deno",
		// D-161 — Clojure manifests, missed live on a Leiningen project whose
		// JDBC driver carried three real advisories.
		"project.clj": "leiningen",
		"deps.edn":    "clojure",
	}
	for name, wantEco := range gaps {
		if eco, ok := classifyGapManifest(name); !ok || eco != wantEco {
			t.Errorf("classifyGapManifest(%q) = (%q,%v), want (%q,true)", name, eco, ok, wantEco)
		}
	}
	// Supported manifests must NOT be gap manifests: a dir carrying one is claimed
	// by a real adapter, and a dep-less one is legitimately empty, not a gap.
	for _, name := range []string{
		"package.json", "requirements.txt", "pyproject.toml", "composer.json", "go.mod",
		"packages.lock.json", "packages.config", "Gemfile", "README.md",
		// Adapter-handled .lock files must be excluded from the hail-mary catch-all —
		// their directories are claimed and scanned, not disclosed as unknown gaps.
		"Cargo.lock", "composer.lock", "yarn.lock", "Gemfile.lock", "Pipfile.lock", "paket.lock",
		// OPU-18 dedication guardrail: a general extension is NEVER blanket-added,
		// so an arbitrary file sharing that suffix stays silent. Only the specific
		// mix.exs / Directory.Packages.props / .terraform.lock.hcl names disclose.
		"Custom.props", "Build.targets", "foo.exs", "main.hcl", "config.yaml",
	} {
		if _, ok := classifyGapManifest(name); ok {
			t.Errorf("classifyGapManifest(%q) should be false (supported or non-manifest)", name)
		}
	}
}

// OPU-18: a genuinely-unrecognized .lock (no name-table entry, no adapter) still
// falls through to the hail-mary catch-all as "unknown" — the net is widened for
// attribution, not narrowed.
func TestClassifyGapUnknownLockStillCatchAll(t *testing.T) {
	if eco, ok := classifyGapManifest("obscuretool.lock"); !ok || eco != "unknown" {
		t.Errorf("classifyGapManifest(obscuretool.lock) = (%q,%v), want (unknown,true)", eco, ok)
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

// TestRecognizedGapManifestsAIAgentConfig covers OPU-37's discovery half: a
// lockfile-less directory carrying only an AI-coding-agent config file (the
// exact shape of the real test-repo-runon-only PoC) must be disclosed as an
// "ai-agent-config" gap rather than read as "nothing to scan". Covers both
// indicator shapes: a flat single-component name (aiAgentConfigIndicators)
// and a directory-relative path (aiAgentConfigDirIndicators) — the shipped
// patch added no direct test for either at this layer (only for the
// installsurface-package half: IsPersistenceMarker / AnalyzeAIAgentConfig).
func TestRecognizedGapManifestsAIAgentConfig(t *testing.T) {
	// Flat indicator: a bare .cursorrules file with nothing else present.
	flatDir := t.TempDir()
	writeGapFile(t, filepath.Join(flatDir, ".cursorrules"), "some rules")
	got := recognizedGapManifests(flatDir)
	if len(got) != 1 || got[0].File != ".cursorrules" || got[0].Ecosystem != "ai-agent-config" {
		t.Fatalf("recognizedGapManifests = %+v, want one .cursorrules (ai-agent-config)", got)
	}

	// Directory-relative indicator: .vscode/tasks.json, the real
	// test-repo-runon-only shape — a subdirectory + file pair, not a flat
	// top-level entry.
	dirRelDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirRelDir, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeGapFile(t, filepath.Join(dirRelDir, ".vscode", "tasks.json"), "{}")
	got = recognizedGapManifests(dirRelDir)
	if len(got) != 1 || got[0].File != ".vscode/tasks.json" || got[0].Ecosystem != "ai-agent-config" {
		t.Fatalf("recognizedGapManifests = %+v, want one .vscode/tasks.json (ai-agent-config)", got)
	}

	// A directory with neither a dependency manifest nor any AI-agent config
	// indicator must still yield no gap — this marker set must not fire on
	// an ordinary, unrelated file.
	clean := t.TempDir()
	writeGapFile(t, filepath.Join(clean, "README.md"), "# hi")
	if g := recognizedGapManifests(clean); len(g) != 0 {
		t.Errorf("an unrelated file must not be an ai-agent-config gap: %+v", g)
	}
}

// OPU-17 hail-mary: a directory whose only dependency artifact is a lockfile for
// an ecosystem depsnort has no name-table entry or recognizer for is disclosed as
// an unknown-ecosystem gap through the discovery loop, not skipped in silence.
func TestRecognizedGapManifestsCatchAllLock(t *testing.T) {
	dir := t.TempDir()
	writeGapFile(t, filepath.Join(dir, "obscuretool.lock"), "whatever")
	got := recognizedGapManifests(dir)
	if len(got) != 1 || got[0].File != "obscuretool.lock" || got[0].Ecosystem != "unknown" {
		t.Fatalf("recognizedGapManifests = %+v, want one obscuretool.lock (unknown)", got)
	}
	// A directory whose lockfile IS handled by a real adapter must not be disclosed
	// as an unknown gap — the catch-all excludes it.
	claimed := t.TempDir()
	writeGapFile(t, filepath.Join(claimed, "Cargo.lock"), "")
	if g := recognizedGapManifests(claimed); len(g) != 0 {
		t.Errorf("an adapter-handled lock must not be a catch-all gap: %+v", g)
	}
}

// OPU-18: the discovery loop discloses the newly-recognized files end-to-end,
// including a dot-prefixed FILE (.terraform.lock.hcl), proving file-level
// classification has no hidden-file filter (only directory walking skips dots).
func TestRecognizedGapManifestsOPU18(t *testing.T) {
	cases := []struct{ file, eco string }{
		{"mygem.gemspec", "rubygems"},
		{"MyPod.podspec", "cocoapods"},
		{"App.vcxproj", "nuget"},
		{"gradle.lockfile", "gradle"},
		{"mix.exs", "elixir"},
		{".terraform.lock.hcl", "terraform"},
		{"mix.lock", "elixir"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		writeGapFile(t, filepath.Join(dir, c.file), "x")
		got := recognizedGapManifests(dir)
		if len(got) != 1 || got[0].File != c.file || got[0].Ecosystem != c.eco {
			t.Errorf("recognizedGapManifests(%s) = %+v, want one %s (%s)", c.file, got, c.file, c.eco)
		}
	}
	// Guardrail: a directory with only a general-extension non-manifest discloses
	// nothing — the dedication rule holds at the discovery layer too.
	for _, quiet := range []string{"Custom.props", "Build.targets", "helpers.exs"} {
		dir := t.TempDir()
		writeGapFile(t, filepath.Join(dir, quiet), "x")
		if g := recognizedGapManifests(dir); len(g) != 0 {
			t.Errorf("%s must not be disclosed (dedication guardrail): %+v", quiet, g)
		}
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
	got := discoverManifestGaps(root, claimed, false)
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

// OPU-24: a --no-recursive scan must disclose projects in subdirectories it did
// not reach, rather than silently under-covering. (Under the full-send default
// this function is not consulted; it fires only on the shallow escape hatch.)
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
	if !strings.Contains(joined, "additional-project") || !strings.Contains(joined, "--no-recursive") {
		t.Errorf("subdir disclosure should name additional projects and reference --no-recursive: %v", notes)
	}
}

// OPU-21/OPU-24: a same-directory polyglot root is now CO-SCANNED — every
// ecosystem resolves — so it must produce ZERO discovery gaps, where the old
// one-adapter-per-dir rule dropped and disclosed all-but-one.
func TestDiscoveryGapsPolyglotCoScannedNoGaps(t *testing.T) {
	dir := t.TempDir()
	writeGapFile(t, filepath.Join(dir, "package-lock.json"), `{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"}}}`)
	writeGapFile(t, filepath.Join(dir, "requirements.txt"), "flask==2.0.1\n")
	writeGapFile(t, filepath.Join(dir, "go.mod"), "module x\ngo 1.21\n")

	reg := adapterRegistry(true)
	// DetectAll co-scans all three ecosystems in this one directory.
	claimants := reg.DetectAll(dir)
	if len(claimants) != 3 {
		t.Fatalf("DetectAll = %d ecosystems, want 3 (npm, pypi, gomod)", len(claimants))
	}
	scanned := make([]discovered, 0, len(claimants))
	for _, a := range claimants {
		scanned = append(scanned, discovered{Path: dir, Adapter: a})
	}
	// No subdirectories, so a shallow scan of this dir has nothing left to disclose.
	notes := discoveryCoverageGaps(dir, scanned, reg, false)
	if len(notes) != 0 {
		t.Errorf("a co-scanned polyglot dir must produce zero gaps, got %v", notes)
	}
}

// A genuine single-project directory with no subdir projects must produce no
// disclosure — no false alarm.
func TestDiscoveryGapsSingleProjectQuiet(t *testing.T) {
	dir := t.TempDir()
	writeGapFile(t, filepath.Join(dir, "package-lock.json"), `{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"}}}`)

	reg := adapterRegistry(true)
	claimants := reg.DetectAll(dir)
	scanned := make([]discovered, 0, len(claimants))
	for _, a := range claimants {
		scanned = append(scanned, discovered{Path: dir, Adapter: a})
	}
	notes := discoveryCoverageGaps(dir, scanned, reg, false)
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
