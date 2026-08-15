package pypi

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// flatRoot builds a synthetic flat-resolution PyPI root with the given
// pinned direct dependencies, mirroring exactly what parseRequirements
// leaves behind for a provenance-free requirements.txt: every pinned
// package hangs directly off the root, Direct=true, AttrFlatResolution set.
func flatRoot(g *graph.Graph, names ...string) *graph.Node {
	rootID := purl.NewPyPI("app", "0.0.0").String()
	root := g.AddNode(&graph.Node{
		ID: rootID, Ecosystem: "pypi", Name: "app", Version: "0.0.0",
		Attr: map[string]string{graph.AttrFlatResolution: "pypi"},
	})
	g.MarkRoot(rootID)
	for _, name := range names {
		id := purl.NewPyPI(name, "1.0.0").String()
		g.AddNode(&graph.Node{
			ID: id, Ecosystem: "pypi", Name: name, Version: "1.0.0",
			Direct: true, Attr: map[string]string{"pypi.source": "requirements.txt"},
		})
		g.AddEdge(rootID, id, graph.EdgeDependsOn)
	}
	return root
}

func hasEdge(g *graph.Graph, from, to string, t graph.EdgeType) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Type == t {
			return true
		}
	}
	return false
}

func TestReconstructDepthResolvesFoundParentAndLeavesRootLevelUndetermined(t *testing.T) {
	g := graph.New()
	root := flatRoot(g, "a", "b", "c")
	a := purl.NewPyPI("a", "1.0.0").String()
	b := purl.NewPyPI("b", "1.0.0").String()
	c := purl.NewPyPI("c", "1.0.0").String()

	requiresDist := map[string][]string{
		coordKey(g.Get(a)): {"b"},
		coordKey(g.Get(b)): {},
		coordKey(g.Get(c)): {},
	}

	ReconstructDepth(g, []*graph.Node{root}, requiresDist)

	if !hasEdge(g, a, b, graph.EdgeDependsOn) {
		t.Error("expected a -> b to be drawn from a's requires_dist")
	}
	if hasEdge(g, root.ID, b, graph.EdgeDependsOn) {
		t.Error("expected root -> b to be removed once a real parent was found")
	}
	if n := g.Get(b); n == nil || n.Direct {
		t.Errorf("b.Direct = %+v, want false", n)
	}
	if n := g.Get(b); n == nil || n.Attr[AttrParentStatus] != "resolved" {
		t.Errorf("b parent_status = %v, want resolved", n)
	}
	if n := g.Get(c); n == nil || n.Attr[AttrParentStatus] != "root-level" {
		t.Errorf("c parent_status = %v, want root-level", n)
	}
	if root.Attr[AttrReconstruction] != "partial" {
		t.Errorf("root reconstruction = %q, want partial", root.Attr[AttrReconstruction])
	}
	if root.Attr[graph.AttrFlatResolution] != "pypi" {
		t.Errorf("AttrFlatResolution = %q, want still present (\"pypi\")", root.Attr[graph.AttrFlatResolution])
	}
}

func TestReconstructDepthFullResolutionClearsFlatFlag(t *testing.T) {
	g := graph.New()
	root := flatRoot(g, "a", "b")
	a := purl.NewPyPI("a", "1.0.0").String()
	b := purl.NewPyPI("b", "1.0.0").String()

	// A mutual pair: each names the other, so both find a real parent among
	// their pinned peers and resolved == len(pinned).
	requiresDist := map[string][]string{
		coordKey(g.Get(a)): {"b"},
		coordKey(g.Get(b)): {"a"},
	}

	ReconstructDepth(g, []*graph.Node{root}, requiresDist)

	if root.Attr[AttrReconstruction] != "complete" {
		t.Errorf("root reconstruction = %q, want complete", root.Attr[AttrReconstruction])
	}
	if _, ok := root.Attr[graph.AttrFlatResolution]; ok {
		t.Errorf("AttrFlatResolution still present after full resolution: %+v", root.Attr)
	}
}

func TestReconstructDepthDiamondDrawsBothParentEdges(t *testing.T) {
	g := graph.New()
	flatRoot(g, "a", "b", "c")
	a := purl.NewPyPI("a", "1.0.0").String()
	b := purl.NewPyPI("b", "1.0.0").String()
	c := purl.NewPyPI("c", "1.0.0").String()
	root := g.Get(g.Roots[0])

	// Both a and b declare c as a dependency: a diamond.
	requiresDist := map[string][]string{
		coordKey(g.Get(a)): {"c"},
		coordKey(g.Get(b)): {"c"},
		coordKey(g.Get(c)): {},
	}

	ReconstructDepth(g, []*graph.Node{root}, requiresDist)

	if !hasEdge(g, a, c, graph.EdgeDependsOn) {
		t.Error("expected a -> c")
	}
	if !hasEdge(g, b, c, graph.EdgeDependsOn) {
		t.Error("expected b -> c")
	}
	if n := g.Get(c); n == nil || n.Attr[AttrParentStatus] != "resolved" {
		t.Errorf("c parent_status = %v, want resolved", n)
	}
}

// pep508 extras-gating (pep508.GatedByExtra) is applied upstream, in
// registry.PyPIDepsClient.RequiresDist, before ReconstructDepth ever sees a
// name list — by the time it reaches here, an extras-conditional dependency
// has already been dropped from the list. This constructs the requiresDist
// map exactly as that upstream filtering would leave it (b's name simply
// absent from a's list) and confirms no edge is drawn on b's behalf.
func TestReconstructDepthExtrasGatedEntryFormsNoEdge(t *testing.T) {
	g := graph.New()
	root := flatRoot(g, "a", "b")
	a := purl.NewPyPI("a", "1.0.0").String()
	b := purl.NewPyPI("b", "1.0.0").String()

	requiresDist := map[string][]string{
		coordKey(g.Get(a)): {}, // "b ; extra == 'security'" was filtered out upstream
		coordKey(g.Get(b)): {},
	}

	ReconstructDepth(g, []*graph.Node{root}, requiresDist)

	if hasEdge(g, a, b, graph.EdgeDependsOn) {
		t.Error("no edge should form for an extras-gated dependency this tool never confirmed was requested")
	}
	if !hasEdge(g, root.ID, b, graph.EdgeDependsOn) {
		t.Error("root -> b should remain since no real parent was found")
	}
	if n := g.Get(b); n == nil || n.Attr[AttrParentStatus] == "resolved" {
		t.Errorf("b parent_status = %v, must not be resolved", n)
	}
}

func TestReconstructDepthRootsAreIndependent(t *testing.T) {
	g := graph.New()
	rootA := g.AddNode(&graph.Node{
		ID: "pkg:pypi/proj-a@0.0.0", Ecosystem: "pypi", Name: "proj-a", Version: "0.0.0",
		Attr: map[string]string{graph.AttrFlatResolution: "pypi"},
	})
	g.MarkRoot(rootA.ID)
	x := purl.NewPyPI("x", "1.0.0").String()
	g.AddNode(&graph.Node{ID: x, Ecosystem: "pypi", Name: "x", Version: "1.0.0", Direct: true})
	g.AddEdge(rootA.ID, x, graph.EdgeDependsOn)

	rootB := g.AddNode(&graph.Node{
		ID: "pkg:pypi/proj-b@0.0.0", Ecosystem: "pypi", Name: "proj-b", Version: "0.0.0",
		Attr: map[string]string{graph.AttrFlatResolution: "pypi"},
	})
	g.MarkRoot(rootB.ID)
	// y, pinned under root B, happens to share the SAME name x depends on in
	// a completely unrelated project's requires_dist — this must never
	// produce a cross-root edge.
	y := purl.NewPyPI("y", "1.0.0").String()
	g.AddNode(&graph.Node{ID: y, Ecosystem: "pypi", Name: "y", Version: "1.0.0", Direct: true})
	g.AddEdge(rootB.ID, y, graph.EdgeDependsOn)

	requiresDist := map[string][]string{
		coordKey(g.Get(x)): {"y"}, // names a package that only exists under root B
		coordKey(g.Get(y)): {},
	}

	ReconstructDepth(g, []*graph.Node{rootA, rootB}, requiresDist)

	if hasEdge(g, x, y, graph.EdgeDependsOn) {
		t.Error("root A's pinned package must never draw an edge into root B's tree")
	}
	if n := g.Get(y); n == nil || !n.Direct {
		t.Errorf("y should remain a direct dependency of root B: %+v", n)
	}
}

// TestReconstructDepthRealRequestsTreeFromCompoundSpecifiers is the end-to-end
// regression test for the reported finding (HoneyBadger Vanguard, iHBV-TM-022).
//
// It reproduces the exact scenario the report observed: a flat, provenance-free
// pip-freeze pin of requests plus its four real dependencies, with requests'
// verbatim published requires_dist. Three of those four entries are comma-joined
// compound specifiers.
//
// Pre-fix, pep508.Split corrupted those three names ("idna<4," etc.), so they
// failed the name match in reconstructRoot, fell through to the "no parent
// found" branch, and were stamped pypi.parent_status "root-level" at depth 1 —
// depSNORT's own "confidently a direct dependency" claim — while certifi (the
// single-clause control) resolved correctly. Nothing was disclosed.
func TestReconstructDepthRealRequestsTreeFromCompoundSpecifiers(t *testing.T) {
	g := graph.New()
	deps := []string{"charset-normalizer", "idna", "urllib3", "certifi"}
	root := flatRoot(g, append([]string{"requests"}, deps...)...)
	requests := purl.NewPyPI("requests", "1.0.0").String()

	// The names as parseRequiresDist yields them post-fix, from requests'
	// real metadata: ["charset_normalizer<4,>=2", "idna<4,>=2.5",
	// "urllib3<3,>=1.26", "certifi>=2017.4.17"].
	requiresDist := map[string][]string{
		coordKey(g.Get(requests)): deps,
	}
	for _, d := range deps {
		requiresDist[coordKey(g.Get(purl.NewPyPI(d, "1.0.0").String()))] = nil
	}

	ReconstructDepth(g, []*graph.Node{root}, requiresDist)

	for _, d := range deps {
		id := purl.NewPyPI(d, "1.0.0").String()
		n := g.Get(id)
		if n == nil {
			t.Fatalf("%s missing from the graph", d)
		}
		if got := n.Attr[AttrParentStatus]; got != "resolved" {
			t.Errorf("%s parent_status = %q, want \"resolved\" (the reported bug stamped these \"root-level\")", d, got)
		}
		if n.Depth != 2 {
			t.Errorf("%s depth = %d, want 2", d, n.Depth)
		}
		if n.Direct {
			t.Errorf("%s is still marked Direct; it is a transitive dependency of requests", d)
		}
		if !hasEdge(g, requests, id, graph.EdgeDependsOn) {
			t.Errorf("missing requests -> %s edge", d)
		}
		if hasEdge(g, root.ID, id, graph.EdgeDependsOn) {
			t.Errorf("synthetic root -> %s edge was not retired", d)
		}
	}

	// requests itself genuinely is top-level here.
	if got := g.Get(requests).Attr[AttrParentStatus]; got != "root-level" {
		t.Errorf("requests parent_status = %q, want \"root-level\"", got)
	}
	if g.Get(requests).Depth != 1 {
		t.Errorf("requests depth = %d, want 1", g.Get(requests).Depth)
	}
}
