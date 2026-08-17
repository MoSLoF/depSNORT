package npm

import (
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

	want := map[string]string{
		"pkg:npm/registry-dep@1.2.3": graph.SourceRegistry,
		"pkg:npm/forked-dep@2.0.0":   graph.SourceGit,
		"pkg:npm/local-dep@0.1.0":    graph.SourcePath,
	}
	for id, wantClass := range want {
		n := g.Get(id)
		if n == nil {
			t.Errorf("node %s missing", id)
			continue
		}
		if got, _ := n.SourceOf(); got != wantClass {
			t.Errorf("%s: class = %q, want %q", id, got, wantClass)
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
