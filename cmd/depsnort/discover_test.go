package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

const wsRoot = "testdata/workspace"

func TestDiscoverFindsEveryProject(t *testing.T) {
	adapters := adapterRegistry(true)
	found, err := discoverProjects(wsRoot, adapters, false)
	if err != nil {
		t.Fatalf("discoverProjects: %v", err)
	}
	if len(found) != 8 {
		var paths []string
		for _, f := range found {
			paths = append(paths, f.Path)
		}
		t.Fatalf("found %d projects, want 8: %v", len(found), paths)
	}

	byPath := map[string]string{}
	for _, f := range found {
		byPath[filepath.ToSlash(f.Path)] = f.Adapter.Name()
	}
	want := map[string]string{
		wsRoot + "/repo-a":           "npm",
		wsRoot + "/repo-b":           "npm",
		wsRoot + "/py-repo":          "pypi",
		wsRoot + "/nested/deep-repo": "npm",
		wsRoot + "/ruby-repo":        "gem",
		wsRoot + "/rust-repo":        "cargo",
		wsRoot + "/php-repo":         "composer",
		wsRoot + "/dotnet-repo":      "nuget",
	}
	for p, eco := range want {
		if got, ok := byPath[p]; !ok {
			t.Errorf("missing project %s", p)
		} else if got != eco {
			t.Errorf("%s claimed by %q, want %q", p, got, eco)
		}
	}
}

// The decoy lockfile inside node_modules must never be discovered. Walking
// node_modules would resolve vendored copies as first-class projects and, on a
// real workspace, take effectively forever.
func TestDiscoverSkipsNodeModules(t *testing.T) {
	adapters := adapterRegistry(true)
	found, err := discoverProjects(wsRoot, adapters, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if strings.Contains(filepath.ToSlash(f.Path), "node_modules") {
			t.Errorf("discovery descended into node_modules: %s", f.Path)
		}
	}
}

// OPU-21: a single directory carrying manifests for several ecosystems yields one
// project root PER ECOSYSTEM (co-scan), where the old one-adapter-per-dir rule
// kept only the first.
func TestDiscoverCoScansAllEcosystems(t *testing.T) {
	root := t.TempDir()
	writeGapFile(t, filepath.Join(root, "package-lock.json"), `{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"}}}`)
	writeGapFile(t, filepath.Join(root, "requirements.txt"), "flask==2.0.1\n")
	writeGapFile(t, filepath.Join(root, "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nDEPENDENCIES\n  rake\n")

	adapters := adapterRegistry(true)
	found, err := discoverProjects(root, adapters, false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range found {
		if filepath.Clean(f.Path) == filepath.Clean(root) {
			got[f.Adapter.Name()] = true
		}
	}
	for _, eco := range []string{"npm", "pypi", "gem"} {
		if !got[eco] {
			t.Errorf("co-scan missing %s in the polyglot root; got %v", eco, got)
		}
	}
}

func discoverHas(found []discovered, sub string) bool {
	for _, f := range found {
		if strings.Contains(filepath.ToSlash(f.Path), sub) {
			return true
		}
	}
	return false
}

// OPU-19/OPU-25: dist/, build/, and target/ are all SCANNED by default (a real
// dependency-bearing project under any of them is exposed); node_modules stays
// pruned; -no-build-dirs suppresses build/target but not dist/.
func TestDiscoverBuildDirRules(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "svc", "dist"))
	writeGapFile(t, filepath.Join(root, "svc", "dist", "requirements.txt"), "requests==2.20.0\n")
	mkdirAll(t, filepath.Join(root, "node_modules", "leftpad"))
	writeGapFile(t, filepath.Join(root, "node_modules", "leftpad", "requirements.txt"), "evil==1.0.0\n")
	// A REAL tooling project under build/ (the Titanis case: src/build/Tool/…).
	mkdirAll(t, filepath.Join(root, "src", "build", "Tooling"))
	writeGapFile(t, filepath.Join(root, "src", "build", "Tooling", "requirements.txt"), "tool==1.0.0\n")
	// A real project under target/ that is NOT an artifact subdir.
	mkdirAll(t, filepath.Join(root, "app", "target", "MyProject"))
	writeGapFile(t, filepath.Join(root, "app", "target", "MyProject", "requirements.txt"), "real==1.0.0\n")

	adapters := adapterRegistry(true)

	found, err := discoverProjects(root, adapters, false)
	if err != nil {
		t.Fatal(err)
	}
	if !discoverHas(found, "/svc/dist") {
		t.Error("dist/ manifest must be scanned by default")
	}
	if !discoverHas(found, "/src/build/Tooling") {
		t.Error("a real project under build/ must be scanned by default (OPU-25, Titanis case)")
	}
	if !discoverHas(found, "/target/MyProject") {
		t.Error("a real project under target/ must be scanned by default (OPU-25)")
	}
	if discoverHas(found, "node_modules") {
		t.Error("node_modules manifest must stay pruned")
	}

	noBuild, err := discoverProjects(root, adapters, true)
	if err != nil {
		t.Fatal(err)
	}
	if discoverHas(noBuild, "/src/build/") || discoverHas(noBuild, "/target/") {
		t.Error("-no-build-dirs must suppress build/ and target/")
	}
	if !discoverHas(noBuild, "/svc/dist") {
		t.Error("-no-build-dirs must NOT suppress dist/")
	}
}

// OPU-25: generated-artifact subdirs INSIDE a build/target tree are pruned (their
// manifests are copies of ones resolved elsewhere), but a directory of the same
// name OUTSIDE a build tree is real source and is scanned.
func TestDiscoverBuildArtifactPruneIsPathContextual(t *testing.T) {
	root := t.TempDir()
	// Maven: root pom + a generated pom under target/classes/META-INF/maven/….
	mkdirAll(t, filepath.Join(root, "mvn"))
	writeGapFile(t, filepath.Join(root, "mvn", "pom.xml"), "<project/>")
	mkdirAll(t, filepath.Join(root, "mvn", "target", "classes", "META-INF", "maven", "g", "a"))
	writeGapFile(t, filepath.Join(root, "mvn", "target", "classes", "META-INF", "maven", "g", "a", "pom.xml"), "<project/>")
	// Rust: root Cargo.lock + a packaged copy under target/package/app-0.1.0/.
	mkdirAll(t, filepath.Join(root, "rs"))
	writeGapFile(t, filepath.Join(root, "rs", "Cargo.lock"), "[[package]]\nname=\"app\"\nversion=\"0.1.0\"\n")
	mkdirAll(t, filepath.Join(root, "rs", "target", "package", "app-0.1.0"))
	writeGapFile(t, filepath.Join(root, "rs", "target", "package", "app-0.1.0", "Cargo.lock"), "[[package]]\nname=\"app\"\nversion=\"0.1.0\"\n")
	// A real source dir named "package" and one named "resources", NOT under a
	// build tree — must be scanned (path-contextual prune).
	mkdirAll(t, filepath.Join(root, "src", "package"))
	writeGapFile(t, filepath.Join(root, "src", "package", "requirements.txt"), "realpkg==1.0.0\n")
	mkdirAll(t, filepath.Join(root, "app", "resources"))
	writeGapFile(t, filepath.Join(root, "app", "resources", "requirements.txt"), "realres==1.0.0\n")

	adapters := adapterRegistry(true)
	found, err := discoverProjects(root, adapters, false)
	if err != nil {
		t.Fatal(err)
	}
	// Artifact copies suppressed.
	if discoverHas(found, "target/classes") {
		t.Error("Maven target/classes copy must be pruned")
	}
	if discoverHas(found, "target/package") {
		t.Error("Rust target/package copy must be pruned")
	}
	// Real same-named source dirs outside build trees preserved.
	if !discoverHas(found, "/src/package") {
		t.Error("a real src/package (outside a build tree) must be scanned — prune is path-contextual")
	}
	if !discoverHas(found, "/app/resources") {
		t.Error("a real app/resources (outside a build tree) must be scanned — prune is path-contextual")
	}
}

// OPU-22: a manifest deeper than the old maxWalkDepth of 8 must be discovered —
// the depth bound is gone.
func TestDiscoverNoDepthBound(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "svc")
	mkdirAll(t, deep)
	writeGapFile(t, filepath.Join(deep, "requirements.txt"), "numpy==1.0.0\n")

	adapters := adapterRegistry(true)
	found, err := discoverProjects(root, adapters, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if strings.Contains(filepath.ToSlash(f.Path), "/j/svc") {
			return
		}
	}
	t.Errorf("a manifest at depth 11 was not discovered (depth bound not removed): %+v", found)
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverIsDeterministic(t *testing.T) {
	adapters := adapterRegistry(true)
	var first []string
	for i := 0; i < 6; i++ {
		found, err := discoverProjects(wsRoot, adapters, false)
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, f := range found {
			paths = append(paths, f.Path)
		}
		if i == 0 {
			first = paths
			continue
		}
		for j := range paths {
			if paths[j] != first[j] {
				t.Fatalf("run %d differs at %d: %s vs %s", i, j, paths[j], first[j])
			}
		}
	}
}

// The point of merging into one graph: a package at the same version in two
// repos is ONE node, and both repos appear as roots.
func TestMergeDedupesSharedDependencies(t *testing.T) {
	adapters := adapterRegistry(true)
	found, err := discoverProjects(wsRoot, adapters, false)
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	for _, p := range found {
		sub, err := p.Adapter.Resolve(p.Path)
		if err != nil {
			t.Fatalf("resolve %s: %v", p.Path, err)
		}
		g.Merge(sub)
	}

	if len(g.Roots) != 8 {
		t.Errorf("roots = %d, want 8 (one per project)", len(g.Roots))
	}
	// shared-dep@1.0.0 appears in repo-a and repo-b but must be a single node.
	shared := g.Get("pkg:npm/shared-dep@1.0.0")
	if shared == nil {
		t.Fatal("shared-dep node missing after merge")
	}
	var count int
	for _, n := range g.SortedNodes() {
		if n.Name == "shared-dep" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("shared-dep appears as %d nodes, want 1 (dedupe failed)", count)
	}
	// Both repos must have an edge into it — that is the blast radius.
	var inbound int
	for _, e := range g.SortedEdges() {
		if e.To == shared.ID && e.Type == graph.EdgeDependsOn {
			inbound++
		}
	}
	if inbound != 2 {
		t.Errorf("shared-dep inbound edges = %d, want 2 (one per repo)", inbound)
	}
	// The decoy inside node_modules must not have contributed anything.
	for _, n := range g.SortedNodes() {
		if strings.Contains(n.Name, "DECOY") || strings.Contains(n.Name, "decoy") {
			t.Errorf("decoy node leaked into the graph: %s", n.ID)
		}
	}
}

func TestMergeIsIdempotent(t *testing.T) {
	adapters := adapterRegistry(true)
	found, _ := discoverProjects(wsRoot, adapters, false)
	g := graph.New()
	for i := 0; i < 2; i++ { // merge everything twice
		for _, p := range found {
			sub, err := p.Adapter.Resolve(p.Path)
			if err != nil {
				t.Fatal(err)
			}
			g.Merge(sub)
		}
	}
	if len(g.Roots) != 8 {
		t.Errorf("roots = %d after double merge, want 8", len(g.Roots))
	}
	for _, n := range g.SortedNodes() {
		if n.Name == "shared-dep" {
			// still one node
			continue
		}
	}
	var edges int
	for _, e := range g.SortedEdges() {
		if e.To == "pkg:npm/shared-dep@1.0.0" {
			edges++
		}
	}
	if edges != 2 {
		t.Errorf("double merge duplicated edges: %d, want 2", edges)
	}
}
