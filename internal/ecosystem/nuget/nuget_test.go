package nuget

import (
	"testing"
)

func TestDetect(t *testing.T) {
	a := New()
	if !a.Detect("testdata") {
		t.Error("should detect testdata directory with packages.lock.json")
	}
	if !a.Detect("testdata/packages.lock.json") {
		t.Error("should detect testdata/packages.lock.json directly")
	}
	if a.Detect("testdata/nonexistent") {
		t.Error("should not detect nonexistent path")
	}
}

func TestResolve(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}

	// Expect: root + Newtonsoft.Json + Serilog + Serilog.Sinks.Console = 4 nodes
	nodes := g.SortedNodes()
	if len(nodes) != 4 {
		for _, n := range nodes {
			t.Logf("  node: %s (name=%s, depth=%d, direct=%v)", n.ID, n.Name, n.Depth, n.Direct)
		}
		t.Fatalf("nodes = %d, want 4", len(nodes))
	}

	// NuGet names are lowercased for deduplication.
	nj := g.Get("pkg:nuget/newtonsoft.json@13.0.1")
	if nj == nil {
		t.Fatal("Newtonsoft.Json node missing (should be lowercased)")
	}
	if !nj.Direct {
		t.Error("Newtonsoft.Json should be direct")
	}

	serilog := g.Get("pkg:nuget/serilog@3.0.1")
	if serilog == nil {
		t.Fatal("Serilog node missing")
	}
	if !serilog.Direct {
		t.Error("Serilog should be direct")
	}

	ssc := g.Get("pkg:nuget/serilog.sinks.console@4.1.0")
	if ssc == nil {
		t.Fatal("Serilog.Sinks.Console node missing")
	}
}

func TestResolveEdges(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Serilog -> Serilog.Sinks.Console edge.
	serilogID := "pkg:nuget/serilog@3.0.1"
	sscID := "pkg:nuget/serilog.sinks.console@4.1.0"
	var found bool
	for _, e := range g.SortedEdges() {
		if e.From == serilogID && e.To == sscID {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing edge: serilog -> serilog.sinks.console")
	}
}

func TestResolveDepths(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	ssc := g.Get("pkg:nuget/serilog.sinks.console@4.1.0")
	if ssc == nil {
		t.Fatal("Serilog.Sinks.Console node missing")
	}
	if ssc.Depth != 2 {
		t.Errorf("Serilog.Sinks.Console depth = %d, want 2", ssc.Depth)
	}
}
