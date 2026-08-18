package npm

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestClassifyResolved(t *testing.T) {
	tests := []struct {
		resolved string
		want     string
	}{
		{"", ""},
		{"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", graph.SourceRegistry},
		// A private or mirrored registry is still a registry: the package has a
		// name@version an advisory feed can answer about.
		{"https://artifactory.internal.example/api/npm/npm/x/-/x-1.0.0.tgz", graph.SourceRegistry},
		{"git+https://github.com/o/r.git#deadbeef", graph.SourceGit},
		{"github:owner/repo#semver:^1.0.0", graph.SourceGit},
		{"file:../local-tool", graph.SourcePath},
	}
	for _, tt := range tests {
		if got, _ := classifyResolved(tt.resolved); got != tt.want {
			t.Errorf("classifyResolved(%q) = %q, want %q", tt.resolved, got, tt.want)
		}
	}
}

func TestGitAndFileDepsDegradeCoverage(t *testing.T) {
	lock := []byte(`{
	  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0",
	         "dependencies": {"registry-dep": "^1.0.0", "forked-dep": "*", "local-dep": "*"}},
	    "node_modules/registry-dep": {"version": "1.2.3",
	      "resolved": "https://registry.npmjs.org/registry-dep/-/registry-dep-1.2.3.tgz"},
	    "node_modules/forked-dep": {"version": "2.0.0",
	      "resolved": "git+https://github.com/example-invalid/forked-dep.git#9f1c0de"},
	    "node_modules/local-dep": {"version": "0.1.0", "resolved": "file:../local-dep"}
	  }
	}`)
	g, err := parseLock(lock)
	if err != nil {
		t.Fatalf("parseLock: %v", err)
	}

	// A non-registry package carries its origin in the PURL (D-42), so a git
	// fork can never share a node with the registry package it forked. The
	// exact encoding of that origin is purl's business, not this test's — what
	// matters here is that each package resolves to one node with the right
	// class, and that only registry packages keep a bare coordinate.
	want := map[string]string{
		"registry-dep": graph.SourceRegistry,
		"forked-dep":   graph.SourceGit,
		"local-dep":    graph.SourcePath,
	}
	got := map[string]string{}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Name == "app" {
			continue
		}
		class, _ := n.SourceOf()
		got[n.Name] = class
		switch class {
		case graph.SourceRegistry:
			if strings.Contains(n.ID, "?") {
				t.Errorf("%s: registry package must keep the bare coordinate, got %q", n.Name, n.ID)
			}
		default:
			if !strings.Contains(n.ID, "source="+class) {
				t.Errorf("%s: node ID %q does not carry its %s origin", n.Name, n.ID, class)
			}
		}
	}
	for name, wantClass := range want {
		if got[name] != wantClass {
			t.Errorf("%s: source class = %q, want %q", name, got[name], wantClass)
		}
	}

	cov := g.Coverage()
	if cov.UnverifiableSources != 2 {
		t.Errorf("UnverifiableSources = %d, want 2 (the git dep and the file dep)",
			cov.UnverifiableSources)
	}
}

// TestV1LockfileMakesNoProvenanceClaim: npm v1 lockfiles carry no `resolved`
// field on nested entries. Absence of evidence must record nothing rather than
// mint an "unknown" gap for every package in every legacy project.
func TestV1LockfileMakesNoProvenanceClaim(t *testing.T) {
	lock := []byte(`{
	  "name": "app", "version": "1.0.0", "lockfileVersion": 1,
	  "dependencies": {"old-dep": {"version": "1.0.0"}}
	}`)
	g, err := parseLock(lock)
	if err != nil {
		t.Fatalf("parseLock: %v", err)
	}
	n := g.Get("pkg:npm/old-dep@1.0.0")
	if n == nil {
		t.Fatal("old-dep missing from graph")
	}
	if _, ok := n.Attr[graph.AttrSourceClass]; ok {
		t.Error("a v1 entry with no resolved URL must record no source class")
	}
	if cov := g.Coverage(); cov.UnverifiableSources != 0 {
		t.Errorf("UnverifiableSources = %d for a v1 lockfile, want 0", cov.UnverifiableSources)
	}
}

// TestGitForkAndRegistryCopyAreDistinctNodes is the npm form of DS-REV-02's
// deferred half. npm can hold the same name@version twice — a registry copy
// hoisted at the top and a git fork nested under a dependency that pinned it —
// and before qualifiers they shared a PURL, so one node survived and the other
// silently overwrote its provenance.
func TestGitForkAndRegistryCopyAreDistinctNodes(t *testing.T) {
	lock := []byte(`{
	  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0", "dependencies": {"dup": "^1.0.0", "wrapper": "^1.0.0"}},
	    "node_modules/dup": {"version": "1.0.0",
	      "resolved": "https://registry.npmjs.org/dup/-/dup-1.0.0.tgz"},
	    "node_modules/wrapper": {"version": "1.0.0",
	      "resolved": "https://registry.npmjs.org/wrapper/-/wrapper-1.0.0.tgz",
	      "dependencies": {"dup": "*"}},
	    "node_modules/wrapper/node_modules/dup": {"version": "1.0.0",
	      "resolved": "git+https://github.com/example-invalid/dup.git#9f1c0de"}
	  }
	}`)
	g, err := parseLock(lock)
	if err != nil {
		t.Fatalf("parseLock: %v", err)
	}

	var registry, git *graph.Node
	for _, n := range g.SortedNodes() {
		if n.Name != "dup" {
			continue
		}
		switch class, _ := n.SourceOf(); class {
		case graph.SourceRegistry:
			registry = n
		case graph.SourceGit:
			git = n
		}
	}
	if registry == nil || git == nil {
		t.Fatalf("want both a registry node and a git node for dup; got registry=%v git=%v",
			registry != nil, git != nil)
	}
	if registry.ID == git.ID {
		t.Fatal("the registry copy and the git fork share a node ID")
	}
	if registry.ID != "pkg:npm/dup@1.0.0" {
		t.Errorf("registry node ID = %q, want the bare coordinate", registry.ID)
	}

	// Only the fork is unverifiable; the registry copy still has a coordinate an
	// advisory feed can answer about.
	if cov := g.Coverage(); cov.UnverifiableSources != 1 {
		t.Errorf("UnverifiableSources = %d, want exactly 1 (the fork)", cov.UnverifiableSources)
	}

	// The edge from wrapper must land on the fork it actually pinned.
	var wrapperEdges []string
	for _, e := range g.SortedEdges() {
		if e.From == "pkg:npm/wrapper@1.0.0" && e.Type == graph.EdgeDependsOn {
			wrapperEdges = append(wrapperEdges, e.To)
		}
	}
	if len(wrapperEdges) != 1 || wrapperEdges[0] != git.ID {
		t.Errorf("wrapper deps = %v, want exactly the git fork %q", wrapperEdges, git.ID)
	}
}
