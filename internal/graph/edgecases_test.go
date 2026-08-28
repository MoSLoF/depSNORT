package graph

import "testing"

// Assessment follow-up (finding #2): graph mutation and traversal were
// undertested on the edge cases — RenameNode, Merge, CountByKind, self-loops and
// cycles — even though they carry the most logic. These pin that behavior.

func TestRenameNodeRewritesEverything(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "old", Kind: KindPackage, Name: "old"})
	g.AddNode(&Node{ID: "child", Kind: KindPackage, Name: "child"})
	g.AddEdge("old", "child", EdgeDependsOn)
	g.MarkRoot("old")

	if !g.RenameNode("old", "new") {
		t.Fatalf("RenameNode must return true on success")
	}
	if _, gone := g.Nodes["old"]; gone {
		t.Errorf("old id must be removed from the node map")
	}
	if n := g.Get("new"); n == nil || n.ID != "new" {
		t.Fatalf("new id must resolve and carry the updated ID, got %+v", n)
	}
	// The edge endpoint is rewritten.
	if e := g.SortedEdges(); len(e) != 1 || e[0].From != "new" || e[0].To != "child" {
		t.Errorf("edge endpoint not rewritten: %+v", e)
	}
	// The root is rewritten.
	if len(g.Roots) != 1 || g.Roots[0] != "new" {
		t.Errorf("root not rewritten: %v", g.Roots)
	}
	// edgeSeen was rebuilt: re-adding the (now renamed) edge must be a no-op.
	g.AddEdge("new", "child", EdgeDependsOn)
	if e := g.SortedEdges(); len(e) != 1 {
		t.Errorf("edgeSeen not rebuilt after rename; duplicate edge added: %+v", e)
	}
	// SortedNodes order carries the new id, not the old.
	for _, n := range g.SortedNodes() {
		if n.ID == "old" {
			t.Errorf("order slice still references the old id")
		}
	}
}

func TestRenameNodeBranches(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Kind: KindPackage})
	g.AddNode(&Node{ID: "b", Kind: KindPackage})

	if !g.RenameNode("a", "a") {
		t.Errorf("rename to same id must be a true no-op")
	}
	if g.RenameNode("missing", "z") {
		t.Errorf("rename of an absent node must return false")
	}
	if g.RenameNode("a", "b") {
		t.Errorf("rename onto an existing id must return false (no clobber)")
	}
	// b must be untouched by the refused clobber.
	if g.Get("b") == nil || g.Get("a") == nil {
		t.Errorf("a refused rename must leave both nodes intact")
	}
}

func TestMergeCombinesNodesEdgesRoots(t *testing.T) {
	a := New()
	a.AddNode(&Node{ID: "root", Kind: KindPackage})
	a.AddNode(&Node{ID: "x", Kind: KindPackage})
	a.AddEdge("root", "x", EdgeDependsOn)
	a.MarkRoot("root")

	b := New()
	b.AddNode(&Node{ID: "x", Kind: KindPackage}) // overlapping id
	b.AddNode(&Node{ID: "y", Kind: KindPackage})
	b.AddEdge("x", "y", EdgeDependsOn)
	b.MarkRoot("root") // duplicate root

	a.Merge(b)
	if len(a.Nodes) != 3 {
		t.Errorf("merge must collapse the overlapping id: want 3 nodes, got %d", len(a.Nodes))
	}
	if len(a.SortedEdges()) != 2 {
		t.Errorf("merge must union edges: want 2, got %d", len(a.SortedEdges()))
	}
	if len(a.Roots) != 1 {
		t.Errorf("merge must not duplicate an existing root: want 1, got %d", len(a.Roots))
	}
	// A nil source is a safe no-op.
	a.Merge(nil)
	if len(a.Nodes) != 3 {
		t.Errorf("Merge(nil) must be a no-op")
	}
}

func TestCountByKind(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "p1", Kind: KindPackage})
	g.AddNode(&Node{ID: "p2", Kind: KindPackage})
	g.AddNode(&Node{ID: "h1", Kind: KindInstallHook})
	m := g.CountByKind()
	if m[KindPackage] != 2 || m[KindInstallHook] != 1 {
		t.Errorf("CountByKind = %v, want package:2 hook:1", m)
	}
}

func TestPathToNodeTerminatesOnCycle(t *testing.T) {
	// a -> b -> a is a cycle; BFS must still terminate and return the shortest
	// chain to b rather than loop forever.
	g := New()
	g.AddNode(&Node{ID: "a", Kind: KindPackage})
	g.AddNode(&Node{ID: "b", Kind: KindPackage})
	g.AddEdge("a", "b", EdgeDependsOn)
	g.AddEdge("b", "a", EdgeDependsOn)
	g.MarkRoot("a")

	path := g.PathToNode("b")
	if len(path) != 2 || path[0] != "a" || path[1] != "b" {
		t.Errorf("PathToNode on a cycle = %v, want [a b]", path)
	}
}

func TestSelfLoopHandling(t *testing.T) {
	// A node that depends on itself must not be an orphan, and PathToNode to a
	// self-looping root-child must terminate.
	g := New()
	g.AddNode(&Node{ID: "root", Kind: KindPackage})
	g.AddNode(&Node{ID: "self", Kind: KindPackage})
	g.AddEdge("root", "self", EdgeDependsOn)
	g.AddEdge("self", "self", EdgeDependsOn) // self-loop
	g.MarkRoot("root")

	for _, o := range g.Orphans() {
		if o.ID == "self" {
			t.Errorf("a reachable self-looping node must not be an orphan")
		}
	}
	if path := g.PathToNode("self"); len(path) != 2 {
		t.Errorf("PathToNode with a self-loop = %v, want [root self]", path)
	}
}

func TestDanglingEdgeIsTolerated(t *testing.T) {
	// AddEdge does no node-existence validation; a dangling endpoint must not
	// crash traversal or wrongly reclassify nodes.
	g := New()
	g.AddNode(&Node{ID: "root", Kind: KindPackage})
	g.MarkRoot("root")
	g.AddEdge("root", "ghost", EdgeDependsOn) // ghost has no node

	if path := g.PathToNode("ghost"); path != nil {
		t.Errorf("PathToNode to a node with no Node entry must be nil, got %v", path)
	}
	if orphans := g.Orphans(); len(orphans) != 0 {
		t.Errorf("a dangling edge target must not appear as an orphan node, got %v", orphans)
	}
}

func TestEmptyGraphIsSafe(t *testing.T) {
	g := New()
	if len(g.SortedNodes()) != 0 || len(g.SortedEdges()) != 0 {
		t.Errorf("a new graph must be empty")
	}
	if len(g.Orphans()) != 0 {
		t.Errorf("an empty graph has no orphans")
	}
	if len(g.CountByKind()) != 0 {
		t.Errorf("an empty graph counts nothing")
	}
	if g.PathToNode("anything") != nil {
		t.Errorf("PathToNode on an empty graph must be nil")
	}
}
