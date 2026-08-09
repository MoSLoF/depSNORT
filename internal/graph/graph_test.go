package graph

import (
	"testing"

	"ihbv.io/depsnort/internal/finding"
)

func TestAddNodeDedupe(t *testing.T) {
	g := New()
	a := g.AddNode(&Node{ID: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0"})
	b := g.AddNode(&Node{ID: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0"})
	if a != b {
		t.Fatal("expected duplicate ID to return the same node pointer")
	}
	if g.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", g.Len())
	}
	if a.Kind != KindPackage {
		t.Errorf("default Kind = %q, want %q", a.Kind, KindPackage)
	}
	if a.Risk != finding.RiskClean {
		t.Errorf("default Risk = %q, want %q", a.Risk, finding.RiskClean)
	}
}

func TestAddEdgeDedupe(t *testing.T) {
	g := New()
	g.AddEdge("a", "b", EdgeDependsOn)
	g.AddEdge("a", "b", EdgeDependsOn)
	g.AddEdge("a", "b", EdgeDeclaresHook) // different type -> distinct edge
	if len(g.Edges) != 2 {
		t.Fatalf("len(Edges) = %d, want 2", len(g.Edges))
	}
}

func TestSortedNodesDeterministic(t *testing.T) {
	g := New()
	for _, id := range []string{"pkg:npm/c@1", "pkg:npm/a@1", "pkg:npm/b@1"} {
		g.AddNode(&Node{ID: id})
	}
	got := g.SortedNodes()
	want := []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1"}
	for i, n := range got {
		if n.ID != want[i] {
			t.Errorf("SortedNodes()[%d] = %q, want %q", i, n.ID, want[i])
		}
	}
}

// Orphan count is the resolver-health metric that found three parser gaps in a
// row on real workspaces (D-18). Pin its semantics.
func TestOrphansIdentifiesUnreachablePackages(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "root", Kind: KindPackage, Name: "root"})
	g.AddNode(&Node{ID: "child", Kind: KindPackage, Name: "child"})
	g.AddNode(&Node{ID: "stranded", Kind: KindPackage, Name: "stranded"})
	g.AddNode(&Node{ID: "hook", Kind: KindInstallHook, Name: "preinstall"})
	g.MarkRoot("root")
	g.AddEdge("root", "child", EdgeDependsOn)
	g.AddEdge("root", "hook", EdgeDeclaresHook)

	orphans := g.Orphans()
	if len(orphans) != 1 || orphans[0].ID != "stranded" {
		t.Fatalf("orphans = %v, want exactly [stranded]", orphans)
	}
	// A root is never an orphan, and non-package kinds are out of scope.
	for _, o := range orphans {
		if o.ID == "root" || o.Kind != KindPackage {
			t.Errorf("unexpected orphan: %+v", o)
		}
	}
}

func TestFullyConnectedGraphHasNoOrphans(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "r", Kind: KindPackage})
	g.AddNode(&Node{ID: "a", Kind: KindPackage})
	g.AddNode(&Node{ID: "b", Kind: KindPackage})
	g.MarkRoot("r")
	g.AddEdge("r", "a", EdgeDependsOn)
	g.AddEdge("a", "b", EdgeDependsOn)
	if n := len(g.Orphans()); n != 0 {
		t.Errorf("orphans = %d, want 0", n)
	}
}
