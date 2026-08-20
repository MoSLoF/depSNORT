package expand

import (
	"context"

	"ihbv.io/depsnort/internal/graph"
)

// Resolver is an external resolved-graph service — deps.dev (Decision D-01
// sanctioned "consume deps.dev for manifest-only inputs"). Unlike the presume
// path, which chooses a version from a constraint, a Resolver returns the WHOLE
// transitive graph for a coordinate with a concrete version on every node: it
// is someone else's resolution, reported rather than derived.
//
// That is why an asserted version is its own truth tier, distinct from
// presumed. Presumed is this tool's guess at what an installer would pick;
// asserted is what a resolver that actually ran says the graph is. It is
// stronger than a guess and weaker than an observed lockfile — the lockfile is
// THIS build's fact, the resolver's answer is A build's fact — so it still may
// not gate (verdict demotes it exactly as it does presumed).
type Resolver interface {
	// Name identifies the service in coverage reports.
	Name() string
	// Resolve returns the fully resolved transitive graph for a coordinate, or
	// ok=false when the service has no record of it. The returned graph's Nodes
	// carry concrete versions; Root is the queried coordinate itself.
	Resolve(ctx context.Context, ecosystem, name, version string) (ResolvedGraph, bool, error)
}

// EcosystemNamer is an optional refinement of Resolver for a DISPATCHING
// resolver that routes different ecosystems to different backends (deps.dev for
// pypi/npm/…, a goproxy resolver for gomod — OPU-13). AssertRoot uses NameFor to
// attribute an asserted node to the backend that actually answered (go-proxy vs
// deps.dev) rather than to the dispatcher, so provenance stays truthful.
type EcosystemNamer interface {
	NameFor(ecosystem string) string
}

// ResolvedRef is one node in a resolver's answer: a concrete coordinate.
type ResolvedRef struct {
	Ecosystem string
	Name      string
	Version   string
}

// ResolvedEdge is a dependency relation, as indices into ResolvedGraph.Nodes.
type ResolvedEdge struct{ From, To int }

// ResolvedGraph is a resolver's answer for one coordinate: every node with a
// concrete version, and the edges between them. Nodes[0] is the queried root.
type ResolvedGraph struct {
	Nodes []ResolvedRef
	Edges []ResolvedEdge
}

// AssertResult is what one AssertRoot call learned.
type AssertResult struct {
	Root string `json:"root"`
	// Asserted is how many nodes were added with a resolver-supplied version.
	Asserted int `json:"asserted"`
	// Resolved is whether the service had an answer for this root at all.
	Resolved bool `json:"resolved"`
}

// AssertRoot merges a resolver's full transitive graph for one observed root
// coordinate, adding a node per resolved dependency with TruthAsserted and the
// edges between them.
//
// It runs BEFORE the presume walk. Its nodes carry concrete versions and a
// COMPLETE subtree (the resolver resolved the whole thing), so the presume walk
// treats an asserted node as a closed frontier and never re-presumes beneath it
// — the two tiers do not fight over the same subtree, and asserted always wins
// because it is the stronger claim.
//
// The root itself is never re-versioned: it was observed from a lockfile, and
// an asserted version for it would demote a fact to a claim. Only its resolved
// dependencies become asserted nodes.
func (w *Walker) AssertRoot(ctx context.Context, g *graph.Graph, root *graph.Node, r Resolver) (AssertResult, error) {
	out := AssertResult{Root: root.ID}
	if g == nil || root == nil || root.Version == "" {
		return out, nil
	}
	// Only registry-origin roots have a coordinate a resolver can speak to
	// (D-41/D-43) — the same guard the presume walk applies.
	if !registryQueryable(root) {
		return out, nil
	}

	rg, ok, err := r.Resolve(ctx, root.Ecosystem, root.Name, root.Version)
	if err != nil || !ok {
		return out, err
	}
	out.Resolved = true

	// Attribute asserted nodes to the backend that actually answered for this
	// ecosystem (go-proxy for gomod, deps.dev otherwise) when the resolver is a
	// dispatcher; fall back to its own Name (OPU-13).
	assertedBy := r.Name()
	if en, isNamer := r.(EcosystemNamer); isNamer {
		if nm := en.NameFor(root.Ecosystem); nm != "" {
			assertedBy = nm
		}
	}
	if len(rg.Nodes) == 0 {
		return out, nil
	}

	// Depth by shortest path from the resolved root (index 0), so an asserted node
	// ladders from the dependency it was resolved under rather than defaulting to
	// 0 — a depth-0 transitive node reads as a project root and corrupts every
	// check keyed on depth or direct-ness (the OPU-04 failure, one tier down).
	depthOf := assertedDepths(rg, root.Depth)

	// Map each resolved node index to a graph node ID. Index 0 is the root,
	// which already exists as an observed node; do not re-add or re-version it.
	ids := make([]string, len(rg.Nodes))
	for i, n := range rg.Nodes {
		if n.Name == "" || n.Version == "" {
			continue
		}
		d := w.declarers[n.Ecosystem]
		if d == nil {
			// No seam for this ecosystem: still record identity so edges land,
			// but a resolver can return ecosystems this build does not expand.
			ids[i] = "pkg:" + n.Ecosystem + "/" + n.Name + "@" + n.Version
		} else {
			id, _ := d.Identify(n.Name, n.Version)
			ids[i] = id
		}
		if i == 0 {
			continue // the root: observed, left as-is
		}
		if ids[i] == "" {
			continue
		}
		if existing := g.Get(ids[i]); existing != nil {
			// A node the lockfile already resolved. Observed beats asserted; do
			// not overwrite a fact with a claim.
			continue
		}
		child := g.AddNode(&graph.Node{
			ID: ids[i], Kind: graph.KindPackage, Ecosystem: n.Ecosystem,
			Name: n.Name, Version: n.Version, Depth: depthOf[i],
		})
		setAttr(child, graph.AttrVersionTruth, graph.TruthAsserted)
		setAttr(child, AttrAssertedBy, assertedBy)
		out.Asserted++
	}

	for _, e := range rg.Edges {
		if e.From < 0 || e.From >= len(ids) || e.To < 0 || e.To >= len(ids) {
			continue
		}
		if ids[e.From] == "" || ids[e.To] == "" {
			continue
		}
		g.AddEdge(ids[e.From], ids[e.To], graph.EdgeDependsOn)
	}
	return out, nil
}

// assertedDepths returns, per resolved-node index, its depth as the shortest
// number of dependency edges from the resolved root (index 0), offset by
// rootDepth — the depth of the coordinate the resolver was queried about. A node
// the edges never reach (a disconnected entry a resolver can legitimately
// return) falls back to rootDepth+1, one layer below the root, rather than 0.
func assertedDepths(rg ResolvedGraph, rootDepth int) []int {
	depth := make([]int, len(rg.Nodes))
	for i := range depth {
		depth[i] = -1
	}
	adj := map[int][]int{}
	for _, e := range rg.Edges {
		if e.From >= 0 && e.From < len(rg.Nodes) && e.To >= 0 && e.To < len(rg.Nodes) {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	if len(rg.Nodes) > 0 {
		depth[0] = 0
		queue := []int{0}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, to := range adj[cur] {
				if depth[to] == -1 {
					depth[to] = depth[cur] + 1
					queue = append(queue, to)
				}
			}
		}
	}
	for i := range depth {
		if depth[i] < 0 {
			depth[i] = 1 // unreachable from the root: place one layer below it
		}
		depth[i] += rootDepth
	}
	return depth
}

// AttrAssertedBy names the resolver that supplied an asserted node's version, so
// a report can attribute the claim rather than present it as the tool's own.
const AttrAssertedBy = "depsnort.asserted_by"
