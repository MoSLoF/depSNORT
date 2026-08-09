package builtin

import "ihbv.io/depsnort/internal/graph"

// hasInstallHook reports whether a package node has install-time code. It checks
// two sources: (1) the install-time subgraph — any EdgeDeclaresHook edge from
// the node, and (2) the npm-specific attribute set before install-surface
// extraction runs. This lets VC-004 and VC-005 escalate on any ecosystem, not
// just npm.
func hasInstallHook(g *graph.Graph, n *graph.Node) bool {
	if n.Attr["npm.hasInstallScript"] == "true" {
		return true
	}
	for _, e := range g.Edges {
		if e.From == n.ID && e.Type == graph.EdgeDeclaresHook {
			return true
		}
	}
	return false
}
