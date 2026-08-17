package rubygems

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// TestSectionsClassifyProvenance: Bundler states a gem's origin outright by
// grouping specs under GEM / GIT / PATH. Both facts were parsed and discarded
// before D-41.
func TestSectionsClassifyProvenance(t *testing.T) {
	lock := []byte(`GIT
  remote: https://github.com/example-invalid/forked-gem.git
  revision: 9f1c0de1
  specs:
    forked-gem (2.0.0)

PATH
  remote: vendor/local-gem
  specs:
    local-gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rake (13.0.6)

PLATFORMS
  ruby

DEPENDENCIES
  forked-gem!
  local-gem!
  rake

BUNDLED WITH
   2.3.26
`)
	g, err := parseGemfileLock("testdata", lock)
	if err != nil {
		t.Fatalf("parseGemfileLock: %v", err)
	}

	want := map[string]string{
		"pkg:gem/forked-gem@2.0.0": graph.SourceGit,
		"pkg:gem/local-gem@0.1.0":  graph.SourcePath,
		"pkg:gem/rake@13.0.6":      graph.SourceRegistry,
	}
	for id, wantClass := range want {
		n := g.Get(id)
		if n == nil {
			t.Errorf("node %s missing", id)
			continue
		}
		class, ref := n.SourceOf()
		if class != wantClass {
			t.Errorf("%s: class = %q, want %q", id, class, wantClass)
		}
		if ref == "" {
			t.Errorf("%s: no source ref recorded; the report must be able to name the origin", id)
		}
	}

	cov := g.Coverage()
	if cov.UnverifiableSources != 2 {
		t.Errorf("UnverifiableSources = %d, want 2 (the git gem and the path gem)",
			cov.UnverifiableSources)
	}
}

// TestAllGemSourceIsClean: the ordinary case must stay silent.
func TestAllGemSourceIsClean(t *testing.T) {
	g, err := New().Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cov := g.Coverage(); cov.UnverifiableSources != 0 {
		t.Errorf("a rubygems.org-only lockfile reported %d unverifiable source(s): %v",
			cov.UnverifiableSources, cov.UnverifiableSourceDetails)
	}
}
