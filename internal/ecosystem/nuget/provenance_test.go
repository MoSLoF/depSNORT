package nuget

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// TestProjectReferenceIsLocalSource: a "Project" entry is a sibling project in
// the solution — source nuget.org has never seen — while Direct/Transitive
// entries came from a feed.
func TestProjectReferenceIsLocalSource(t *testing.T) {
	lock := []byte(`{
	  "version": 1,
	  "dependencies": {
	    "net8.0": {
	      "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3"},
	      "Acme.Internal.Core": {"type": "Project", "resolved": "1.0.0"}
	    }
	  }
	}`)
	g, err := parsePackagesLock("testdata", lock)
	if err != nil {
		t.Fatalf("parsePackagesLock: %v", err)
	}

	if class, _ := g.Get("pkg:nuget/acme.internal.core@1.0.0").SourceOf(); class != graph.SourcePath {
		t.Errorf("project reference class = %q, want %q", class, graph.SourcePath)
	}
	if class, _ := g.Get("pkg:nuget/newtonsoft.json@13.0.3").SourceOf(); class != graph.SourceRegistry {
		t.Errorf("feed package class = %q, want %q", class, graph.SourceRegistry)
	}
	if cov := g.Coverage(); cov.UnverifiableSources != 1 {
		t.Errorf("UnverifiableSources = %d, want 1 (the project reference)", cov.UnverifiableSources)
	}
}
