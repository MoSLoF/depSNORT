package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// D-154/OPU-41: D-152 proved the propagation vocabulary (CapPropagate,
// graph.EdgeRepublish, VC-002k) was already ecosystem-neutral — nothing in
// the check or the graph wiring names npm — but the ONLY marker table
// feeding it only recognized npm-family publish verbs. This is the
// end-to-end proof for a non-npm ecosystem: a real Shai-Hulud-shaped
// RubyGems hook (extconf.rb shelling out to `gem push`) must fire VC-002k
// and draw the republish edge exactly as the npm case does, with no
// ecosystem-specific code path added anywhere between AnalyzeRuby and the
// shipping check pack.

func d154RubyGraph(t *testing.T, extconfRb string) *graph.Graph {
	t.Helper()
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:gem/wormy@1.0.0", Kind: graph.KindPackage, Ecosystem: "rubygems",
		Name: "wormy", Version: "1.0.0",
	})
	g.MarkRoot(pkg.ID)
	surface := installsurface.AnalyzeRuby(extconfRb, "", "")
	instsurf.AddToGraph(g, pkg, surface)
	return g
}

func d154VC002k(t *testing.T, g *graph.Graph) []finding.Finding {
	t.Helper()
	var out []finding.Finding
	for _, f := range Default().RunAll(&check.Context{Graph: g}) {
		if f.CheckID == "VC-002k" {
			out = append(out, f)
		}
	}
	return out
}

// TestD154RubyGemsPublishingHookFiresVC002k is the detection itself, for the
// ecosystem D-152 could not reach.
func TestD154RubyGemsPublishingHookFiresVC002k(t *testing.T) {
	extconf := "require 'mkmf'\nsystem('gem build wormy.gemspec')\nsystem('gem push wormy-1.0.0.gem')\ncreate_makefile('wormy')\n"
	g := d154RubyGraph(t, extconf)
	got := d154VC002k(t, g)
	if len(got) != 1 {
		t.Fatalf("a publishing RubyGems extconf.rb must fire VC-002k exactly once, got %v", got)
	}
	if !strings.Contains(got[0].Title, "publishes to a package registry") {
		t.Errorf("unexpected title: %q", got[0].Title)
	}
	if got[0].Severity != finding.SevCritical || got[0].GateClass != finding.GateBlock {
		t.Errorf("VC-002k must be critical+block regardless of ecosystem, got %s %s", got[0].Severity, got[0].GateClass)
	}
}

// TestD154RubyGemsRepublishEdgeIsDrawn: the graph wiring (instsurf.AddToGraph)
// must be exactly as ecosystem-neutral as the D-152 decision claims — this is
// the same edge assertion as the npm case, on a rubygems node.
func TestD154RubyGemsRepublishEdgeIsDrawn(t *testing.T) {
	g := d154RubyGraph(t, "system('gem push wormy-1.0.0.gem')")
	found := false
	for _, e := range g.Edges {
		if e.Type == graph.EdgeRepublish {
			if e.To != "pkg:gem/wormy@1.0.0" {
				t.Errorf("the republish edge must point back at the package, got %q", e.To)
			}
			found = true
		}
	}
	if !found {
		t.Error("a propagating RubyGems hook must create a graph.EdgeRepublish edge")
	}
}

// TestD154RubyGemsOrdinaryExtconfDrawsNoRepublishEdge is the boundary: an
// ordinary native-extension build must not be flagged.
func TestD154RubyGemsOrdinaryExtconfDrawsNoRepublishEdge(t *testing.T) {
	g := d154RubyGraph(t, "require 'mkmf'\ncreate_makefile('wormy')\n")
	for _, e := range g.Edges {
		if e.Type == graph.EdgeRepublish {
			t.Errorf("an ordinary extconf.rb must not create a republish edge: %+v", e)
		}
	}
	if got := d154VC002k(t, g); len(got) != 0 {
		t.Errorf("an ordinary extconf.rb must not fire VC-002k, got %v", got)
	}
}

// TestD154CargoPublishingHookFiresVC002k covers the second new ecosystem
// end-to-end via AnalyzeRust's build.rs path — proving the fix generalizes
// past RubyGems rather than happening to work for one ecosystem only.
func TestD154CargoPublishingHookFiresVC002k(t *testing.T) {
	buildRs := `fn main() { std::process::Command::new("sh").arg("-c").arg("cargo publish --token $CARGO_TOKEN").status().unwrap(); }`
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:cargo/wormy@1.0.0", Kind: graph.KindPackage, Ecosystem: "cargo",
		Name: "wormy", Version: "1.0.0",
	})
	g.MarkRoot(pkg.ID)
	surface := installsurface.AnalyzeRust(buildRs)
	instsurf.AddToGraph(g, pkg, surface)

	got := d154VC002k(t, g)
	if len(got) != 1 {
		t.Fatalf("a publishing Cargo build.rs must fire VC-002k exactly once, got %v", got)
	}

	found := false
	for _, e := range g.Edges {
		if e.Type == graph.EdgeRepublish && e.To == pkg.ID {
			found = true
		}
	}
	if !found {
		t.Error("a propagating build.rs must create a graph.EdgeRepublish edge")
	}
}

// TestD154CargoDryRunDoesNotFireEndToEnd carries the cargo --dry-run boundary
// all the way up to the check, matching the existing npm dry-run assertion.
func TestD154CargoDryRunDoesNotFireEndToEnd(t *testing.T) {
	buildRs := `fn main() { std::process::Command::new("sh").arg("-c").arg("cargo publish --dry-run").status().unwrap(); }`
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:cargo/wormy@1.0.0", Kind: graph.KindPackage, Ecosystem: "cargo",
		Name: "wormy", Version: "1.0.0",
	})
	g.MarkRoot(pkg.ID)
	surface := installsurface.AnalyzeRust(buildRs)
	instsurf.AddToGraph(g, pkg, surface)

	if got := d154VC002k(t, g); len(got) != 0 {
		t.Errorf("a cargo --dry-run rehearsal must not fire VC-002k, got %v", got)
	}
}
