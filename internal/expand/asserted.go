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

// LocalRoot describes a LOCAL main module whose whole build list a resolver can
// resolve from the require set the manifest already parsed — without a proxy
// coordinate for the root itself. It exists because the local project root has no
// published version to fetch (D-41/D-43): its own dependency declarations are all
// the resolver needs to seed resolution.
type LocalRoot struct {
	Ecosystem string
	Name      string
	Version   string            // the root's placeholder/observed version, for node 0
	Requires  []ResolvedRef     // the root's parsed require set (direct + indirect)
	Attr      map[string]string // root-node attributes (e.g. the gomod `go` directive)
}

// LocalRootResolver is an optional refinement of Resolver: it resolves a LOCAL
// main module's ENTIRE build list from the manifest's require set, rather than
// resolving each direct dependency independently and unioning the results.
//
// The union is a superset of the real build list — for a pruned (Go 1.17+) graph
// it re-includes modules and versions the real build prunes away, because each
// dependency is resolved as if it were its own main module. Resolving the main
// module as a whole reproduces the exact build list instead (OPU-15). gomod
// implements this; ecosystems that do not are unaffected (the walker falls back
// to the per-dependency AssertRoot path).
type LocalRootResolver interface {
	ResolveLocalRoot(ctx context.Context, root LocalRoot) (ResolvedGraph, bool, error)
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
	out.Asserted = w.mergeResolved(g, root, rg, assertedByFor(r, root.Ecosystem))
	return out, nil
}

// assertedByFor attributes an asserted node to the backend that actually answered
// for an ecosystem (go-proxy for gomod, deps.dev otherwise) when the resolver is a
// dispatcher; it falls back to the resolver's own Name (OPU-13).
func assertedByFor(r Resolver, ecosystem string) string {
	if en, isNamer := r.(EcosystemNamer); isNamer {
		if nm := en.NameFor(ecosystem); nm != "" {
			return nm
		}
	}
	return r.Name()
}

// mergeResolved folds a resolver's full transitive graph for one root into g:
// index 0 is the root (already an observed node — never re-added or re-versioned),
// and every other node becomes a TruthAsserted node with the resolved edges
// between them. Returns how many asserted nodes were added. Observed beats
// asserted, so a node the lockfile already pinned is left untouched.
func (w *Walker) mergeResolved(g *graph.Graph, root *graph.Node, rg ResolvedGraph, assertedBy string) int {
	if len(rg.Nodes) == 0 {
		return 0
	}

	// Depth by shortest path from the resolved root (index 0), so an asserted node
	// ladders from the dependency it was resolved under rather than defaulting to
	// 0 — a depth-0 transitive node reads as a project root and corrupts every
	// check keyed on depth or direct-ness (the OPU-04 failure, one tier down).
	depthOf := assertedDepths(rg, root.Depth)

	// Map each resolved node index to a graph node ID. Index 0 is the root,
	// which already exists as an observed node; do not re-add or re-version it.
	ids := make([]string, len(rg.Nodes))
	asserted := 0
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
		asserted++
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
	return asserted
}

// assertLocalRoot resolves a main module's ENTIRE build list in one shot, when
// the resolver supports it (LocalRootResolver — gomod), instead of resolving each
// direct dependency independently and unioning (assertDirectSubtrees). The union
// is a superset of the real build list; the whole-root resolution is the exact
// build list (OPU-15). It returns true when it handled the root, so the caller
// skips the per-dependency path.
//
// The root passed to ExpandRoot IS the scanned project root; assertDirectSubtrees
// already aims the resolver at that root's direct dependencies rather than the
// root itself (the root has no proxy coordinate, D-41/D-43), so no per-root
// AssertRoot is bypassed here. The whole-root path only changes HOW those direct
// dependencies are resolved — as one pruned build list instead of a union. The
// resolver decides applicability by ecosystem: a non-gomod root returns ok=false
// and the per-dependency path runs unchanged. On success the whole reachable
// subtree is marked expanded so the presume walk does not re-derive (with weaker,
// presumed claims) what the resolver just stated exactly.
func (w *Walker) assertLocalRoot(ctx context.Context, g *graph.Graph, root *graph.Node, r Resolver,
	inSubtree, expanded map[string]bool, res *Result) bool {

	lrr, ok := r.(LocalRootResolver)
	if !ok || root == nil {
		return false
	}
	reqs := directRequiresOf(g, root)
	if len(reqs) == 0 {
		return false
	}
	rg, ok, err := lrr.ResolveLocalRoot(ctx, LocalRoot{
		Ecosystem: root.Ecosystem, Name: root.Name, Version: root.Version,
		Requires: reqs, Attr: root.Attr,
	})
	if err != nil || !ok {
		return false
	}
	res.Asserted += w.mergeResolved(g, root, rg, assertedByFor(r, root.Ecosystem))
	// The resolver returned the COMPLETE build list under this root; its direct
	// dependencies and their subtrees are closed. Mark everything reachable from
	// the root expanded so the presume walk below never re-derives it — otherwise
	// an observed direct dependency would be presume-expanded and reintroduce the
	// very union artifacts (now as presumed nodes) this path exists to remove.
	for id := range reachable(g, root.ID) {
		inSubtree[id] = true
		expanded[id] = true
	}
	return true
}

// directRequiresOf reads a root's direct dependencies out of the graph as a
// resolver-ready require set (the manifest already parsed them into depth-1
// nodes). For a gomod root that is the go.mod `require` block — direct and
// recorded indirect alike — which is exactly what seeds a whole-build-list
// resolution.
func directRequiresOf(g *graph.Graph, root *graph.Node) []ResolvedRef {
	var out []ResolvedRef
	seen := map[string]bool{}
	for _, id := range directDepIDs(g, root.ID) {
		if seen[id] {
			continue
		}
		seen[id] = true
		n := g.Get(id)
		if n == nil || n.Kind != graph.KindPackage || n.Name == "" || n.Version == "" {
			continue
		}
		out = append(out, ResolvedRef{Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version})
	}
	return out
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
