package pypi

import (
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// Reconstruction facts. Ecosystem-scoped (pypi.*) rather than added to
// graph's shared Attr* vocabulary because this is a PyPI-specific
// capability — no other adapter has a registry endpoint publishing
// per-release requires_dist.
const (
	// AttrReconstruction records, per root, how far requires_dist-based depth
	// reconstruction got: "not-attempted" (registry metadata was never
	// fetched for this scan), "complete" (every pinned entry found a real
	// parent among its pinned peers), or "partial" (at least one stayed
	// root-level or undetermined).
	AttrReconstruction = "pypi.reconstruction"
	// AttrParentStatus records, per pinned package, what reconstruction could
	// determine about its true parent: "resolved" (a real parent was found
	// among its pinned peers), "root-level" (every OTHER pinned peer's
	// requires_dist was known and none named it, so it is confidently a
	// direct dependency), or "undetermined" (at least one peer's
	// requires_dist was never fetched, so a missing parent cannot be ruled
	// out).
	AttrParentStatus = "pypi.parent_status"
	// AttrRequiresDistFetch marks a pinned package whose OWN requires_dist
	// fetch failed — set to "failed".
	AttrRequiresDistFetch = "pypi.requires_dist_fetch"
)

// coordKey mirrors datasource.Coord.Key() so a graph node and a
// registry.PyPIDepsClient.RequiresDist result line up on the same key
// without either side re-deriving the other's format.
func coordKey(n *graph.Node) string {
	return datasource.Coord{Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version}.Key()
}

// ReconstructDepth rebuilds real transitive edges under each root from its
// flat, pinned dependency set, using PyPI's own requires_dist metadata to
// figure out which pinned package actually depends on which.
//
// Non-goal, by design (D-01): matching a requires_dist entry against a
// pinned sibling is by NAME ONLY, never PEP 440 range-satisfaction.
// depSNORT does not reimplement a resolver — a real resolver picks among
// candidate versions and evaluates markers against a target environment;
// this only asks "does some pinned sibling's own published metadata name
// this package at all", which is answerable from public metadata with zero
// execution and no version-range reasoning.
//
// Roots are processed fully independently of one another: a -recursive
// workspace scan's requirements.txt in one project must never draw an edge
// using another, unrelated project's pinned siblings.
func ReconstructDepth(g *graph.Graph, roots []*graph.Node, requiresDist map[string][]string) {
	for _, root := range roots {
		reconstructRoot(g, root, requiresDist)
	}
}

func reconstructRoot(g *graph.Graph, root *graph.Node, requiresDist map[string][]string) {
	var pinned []*graph.Node
	for _, e := range g.SortedEdges() {
		if e.From != root.ID || e.Type != graph.EdgeDependsOn {
			continue
		}
		if n := g.Get(e.To); n != nil {
			pinned = append(pinned, n)
		}
	}
	if len(pinned) == 0 {
		return
	}

	// known tracks which pinned siblings' own requires_dist was actually
	// fetched — only those can be trusted to rule a package OUT as
	// root-level; a sibling whose fetch failed might have been the real
	// parent and there is no way to tell.
	known := make(map[string]bool, len(pinned))
	for _, n := range pinned {
		if _, ok := requiresDist[coordKey(n)]; ok {
			known[n.ID] = true
			continue
		}
		if n.Attr == nil {
			n.Attr = map[string]string{}
		}
		n.Attr[AttrRequiresDistFetch] = "failed"
	}

	resolved := 0
	for _, x := range pinned {
		var foundParents []*graph.Node
		for _, z := range pinned {
			if z.ID == x.ID || !known[z.ID] {
				continue
			}
			for _, dep := range requiresDist[coordKey(z)] {
				if dep == x.Name {
					foundParents = append(foundParents, z)
					break
				}
			}
		}
		if x.Attr == nil {
			x.Attr = map[string]string{}
		}
		if len(foundParents) > 0 {
			// Diamond deps are fully supported: every found parent gets its
			// own edge, not just the first.
			for _, z := range foundParents {
				g.AddEdge(z.ID, x.ID, graph.EdgeDependsOn)
			}
			g.RemoveEdge(root.ID, x.ID, graph.EdgeDependsOn)
			x.Direct = false
			x.Attr[AttrParentStatus] = "resolved"
			resolved++
			continue
		}

		allOtherPeersKnown := true
		for _, z := range pinned {
			if z.ID != x.ID && !known[z.ID] {
				allOtherPeersKnown = false
				break
			}
		}
		if allOtherPeersKnown {
			x.Attr[AttrParentStatus] = "root-level"
		} else {
			x.Attr[AttrParentStatus] = "undetermined"
		}
		// The root edge stays either way: an unresolved parent must not
		// strand the package out of the tree.
	}

	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	if resolved == len(pinned) {
		delete(root.Attr, graph.AttrFlatResolution)
		root.Attr[AttrReconstruction] = "complete"
	} else {
		// AttrFlatResolution is left exactly as it was: Coverage.FlatEcosystems
		// and Coverage.Complete need zero changes to reflect a partial result.
		root.Attr[AttrReconstruction] = "partial"
	}

	assignDepths(g, root.ID)
}
