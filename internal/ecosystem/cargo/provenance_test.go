package cargo

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestClassifySource(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		wantClass string
	}{
		{"absent source is a path/vendored crate", "", graph.SourcePath},
		{"registry", "registry+https://github.com/rust-lang/crates.io-index", graph.SourceRegistry},
		{"sparse registry", "sparse+https://index.crates.io/", graph.SourceRegistry},
		{"git", "git+https://github.com/example-invalid/x?tag=v1#abc", graph.SourceGit},
		{"explicit path", "path+file:///work/crates/x", graph.SourcePath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := classifySource(tt.source)
			if got != tt.wantClass {
				t.Errorf("classifySource(%q) = %q, want %q", tt.source, got, tt.wantClass)
			}
		})
	}
}

// TestVendoredLockClassifiesEverySource is the field case that motivated D-41:
// a graph where the only genuinely un-scannable crates are the vendored forks,
// and where nothing downstream could tell them apart before.
func TestVendoredLockClassifiesEverySource(t *testing.T) {
	g, err := New().Resolve("testdata/vendored")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Non-registry crates carry their origin in the PURL itself (D-42), so a
	// vendored fork and a registry crate of the same name can never share a
	// node. Registry crates keep the bare, canonical coordinate.
	want := map[string]string{
		"pkg:cargo/portable-pty-harbor@0.9.6?source=path": graph.SourcePath,
		"pkg:cargo/vt100-harbor@0.16.9?source=path":       graph.SourcePath,
		"pkg:cargo/libc@0.2.155":                          graph.SourceRegistry,
		"pkg:cargo/bitflags@2.6.0":                        graph.SourceRegistry,
	}
	for id, wantClass := range want {
		n := g.Get(id)
		if n == nil {
			t.Errorf("node %s missing from graph", id)
			continue
		}
		if got, _ := n.SourceOf(); got != wantClass {
			t.Errorf("%s: source class = %q, want %q", id, got, wantClass)
		}
	}

	// The git crate must carry its origin, not just its class: a report that
	// cannot name what it could not verify is barely better than silence, and
	// the origin is what makes two forks of one crate distinguishable.
	var gitNode *graph.Node
	for _, n := range g.SortedNodes() {
		if n.Name == "tally-ho-shim" {
			gitNode = n
		}
	}
	if gitNode == nil {
		t.Fatal("git dependency missing from the graph")
	}
	if class, ref := gitNode.SourceOf(); class != graph.SourceGit || ref == "" {
		t.Errorf("git dependency: class=%q ref=%q", class, ref)
	}
	if !strings.Contains(gitNode.ID, "source=git") {
		t.Errorf("git dependency ID %q does not carry its origin", gitNode.ID)
	}

	cov := g.Coverage()
	if cov.UnverifiableSources != 3 {
		t.Errorf("UnverifiableSources = %d, want 3 (two vendored + one git)", cov.UnverifiableSources)
	}
	if !cov.Incomplete() {
		t.Error("a tree with three non-registry sources must not report complete coverage")
	}
	if cov.Complete {
		t.Error("Complete must be false when sources could not be verified")
	}
}

// TestRootIsNotChargedAsUnverifiable guards the obvious false positive: the
// project being scanned is local source by definition, and Cargo.lock records
// no `source` for it. Charging that would flag every scan of every project.
func TestRootIsNotChargedAsUnverifiable(t *testing.T) {
	g, err := New().Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cov := g.Coverage(); cov.UnverifiableSources != 0 {
		t.Errorf("all-registry tree reported %d unverifiable source(s): %v",
			cov.UnverifiableSources, cov.UnverifiableSourceDetails)
	}
}
