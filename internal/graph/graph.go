// Package graph is the canonical dependency graph — the single source of truth
// every downstream stage annotates (Decision D-03). Nodes are package@version
// (or, once install-surface extraction lands, hook/artifact/sink nodes);
// edges are typed depends-on and the install-time relations.
//
// The node/edge type vocabulary models BOTH trees from day one (Decision D-02):
// the declared subgraph (depends-on) and the install-time subgraph
// (declares-hook, hook-execs, hook-fetches, hook-reads-env, exfil, republish).
// v0 only populates the declared subgraph; the install-time kinds/edges exist
// so that step 5 (install-surface extraction) drops in without a schema change.
package graph

import (
	"sort"

	"ihbv.io/depsnort/internal/finding"
)

// NodeKind distinguishes declared-tree nodes from install-time-subgraph nodes.
type NodeKind string

const (
	KindPackage            NodeKind = "package"             // a resolved package@version
	KindInstallHook        NodeKind = "install-hook"        // preinstall/postinstall/etc.
	KindReferencedArtifact NodeKind = "referenced-artifact" // a file/URL a hook reaches for
	KindSink               NodeKind = "sink"                // credential store / C2 destination
)

// EdgeType is the relation an edge encodes.
type EdgeType string

const (
	EdgeDependsOn    EdgeType = "depends-on"     // declared subgraph
	EdgeDeclaresHook EdgeType = "declares-hook"  // package -> install-hook (crosses the boundary)
	EdgeHookExecs    EdgeType = "hook-execs"     // hook -> referenced-artifact
	EdgeHookFetches  EdgeType = "hook-fetches"   // artifact -> remote artifact
	EdgeHookReadsEnv EdgeType = "hook-reads-env" // hook/artifact -> credential sink
	EdgeExfil        EdgeType = "exfil"          // artifact/sink -> C2
	EdgeRepublish    EdgeType = "republish"      // worm loop back into the declared tree
	EdgeBuildBackend EdgeType = "build-backend"  // consumer -> its PEP 517 build backend package
)

// Node is a single vertex. Adapters set the fact fields (everything except
// Risk/Findings); checks and verdict set Risk and append Findings.
type Node struct {
	ID        string            `json:"id"` // canonical PURL — the identity
	Kind      NodeKind          `json:"kind"`
	Ecosystem string            `json:"ecosystem"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Direct    bool              `json:"direct"`         // a direct dependency of the root
	Depth     int               `json:"depth"`          // shortest distance from a root
	Attr      map[string]string `json:"attr,omitempty"` // freeform FACTS only (no judgment)

	Risk     finding.RiskState `json:"risk"`
	Findings []finding.Finding `json:"findings,omitempty"`
}

// Edge is a typed directed relation between two node IDs.
type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Type EdgeType `json:"type"`
}

// Graph holds nodes keyed by ID plus an edge list. Iteration order is made
// deterministic on demand (SortedNodes) because determinism is a product
// requirement, not a nicety (Decision D-09: a CI gate must be reproducible).
type Graph struct {
	Nodes map[string]*Node `json:"-"`
	Edges []Edge           `json:"edges"`
	Roots []string         `json:"roots"`

	order    []string            // insertion order
	edgeSeen map[string]struct{} // dedupe edges
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		Nodes:    make(map[string]*Node),
		edgeSeen: make(map[string]struct{}),
	}
}

// AddNode inserts n if its ID is new and returns the canonical node for that
// ID. If a node with the same ID already exists, the existing one is returned
// unchanged (first write wins) — this is how transitive duplicates collapse.
func (g *Graph) AddNode(n *Node) *Node {
	if existing, ok := g.Nodes[n.ID]; ok {
		return existing
	}
	if n.Kind == "" {
		n.Kind = KindPackage
	}
	if n.Risk == "" {
		n.Risk = finding.RiskClean
	}
	g.Nodes[n.ID] = n
	g.order = append(g.order, n.ID)
	return n
}

// RenameNode changes a node's ID from old to new, updating the node map,
// insertion order, every edge endpoint, and the root list. No-op if old is
// absent; refuses (returns false) if new already exists, so the caller ensures
// new is free. Used where canonical identity is known only after the graph is
// built: a Cargo workspace root is a source-less crate that gets a provenance
// qualifier during parsing but, as the scan's SUBJECT, should carry the bare
// coordinate.
func (g *Graph) RenameNode(old, new string) bool {
	if old == new {
		return true
	}
	n, ok := g.Nodes[old]
	if !ok {
		return false
	}
	if _, exists := g.Nodes[new]; exists {
		return false
	}
	delete(g.Nodes, old)
	n.ID = new
	g.Nodes[new] = n
	for i, id := range g.order {
		if id == old {
			g.order[i] = new
		}
	}
	for i := range g.Edges {
		if g.Edges[i].From == old {
			g.Edges[i].From = new
		}
		if g.Edges[i].To == old {
			g.Edges[i].To = new
		}
	}
	for i, r := range g.Roots {
		if r == old {
			g.Roots[i] = new
		}
	}
	g.edgeSeen = make(map[string]struct{}, len(g.Edges))
	for _, e := range g.Edges {
		g.edgeSeen[e.From+"\x00"+e.To+"\x00"+string(e.Type)] = struct{}{}
	}
	return true
}

// AddEdge adds a typed edge, deduping exact repeats.
func (g *Graph) AddEdge(from, to string, t EdgeType) {
	key := from + "\x00" + to + "\x00" + string(t)
	if _, ok := g.edgeSeen[key]; ok {
		return
	}
	g.edgeSeen[key] = struct{}{}
	g.Edges = append(g.Edges, Edge{From: from, To: to, Type: t})
}

// RemoveEdge deletes the edge (from, to, t) if present, reporting whether
// anything was removed.
func (g *Graph) RemoveEdge(from, to string, t EdgeType) bool {
	key := from + "\x00" + to + "\x00" + string(t)
	if _, ok := g.edgeSeen[key]; !ok {
		return false
	}
	delete(g.edgeSeen, key)
	for i, e := range g.Edges {
		if e.From == from && e.To == to && e.Type == t {
			g.Edges = append(g.Edges[:i], g.Edges[i+1:]...)
			break
		}
	}
	return true
}

// MarkRoot records id as a graph root (the analyzed project itself).
func (g *Graph) MarkRoot(id string) {
	for _, r := range g.Roots {
		if r == id {
			return
		}
	}
	g.Roots = append(g.Roots, id)
}

// Get returns the node for id, or nil.
func (g *Graph) Get(id string) *Node { return g.Nodes[id] }

// Len is the node count.
func (g *Graph) Len() int { return len(g.Nodes) }

// SortedNodes returns nodes in stable, deterministic (ID-sorted) order.
func (g *Graph) SortedNodes() []*Node {
	ids := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, g.Nodes[id])
	}
	return out
}

// Merge folds src into g: nodes new to g are added, edges are added (deduped),
// and src's roots become additional roots of g.
//
// This is what makes a workspace scan one graph rather than N reports. A package
// at the same version in two repos is the SAME node, so shared dependencies
// collapse and a single flagged package shows its full blast radius across every
// project that pulls it in. Existing nodes are left untouched (first write
// wins), matching AddNode's dedupe rule.
func (g *Graph) Merge(src *Graph) {
	if src == nil {
		return
	}
	for _, n := range src.SortedNodes() {
		g.AddNode(n)
	}
	for _, e := range src.SortedEdges() {
		g.AddEdge(e.From, e.To, e.Type)
	}
	for _, r := range src.Roots {
		g.MarkRoot(r)
	}
}

// SortedEdges returns edges in a stable order (from, to, type).
//
// Edge insertion order follows whatever order an adapter walked its input, and
// lockfile parsing iterates a JSON object — a Go map, whose iteration order is
// deliberately randomized. Without this, two identical scans emit the same edges
// in different orders and a CI diff is noise. Determinism is a product
// requirement (Decision D-09), so emitters must use this rather than raw Edges.
func (g *Graph) SortedEdges() []Edge {
	out := make([]Edge, len(g.Edges))
	copy(out, g.Edges)
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// Orphans returns package nodes that are neither a root nor the target of any
// depends-on edge.
//
// This is a RESOLVER-HEALTH metric, not a security finding. A package present in
// a lockfile but reachable from nothing means the parser missed a relation type.
// Real workspace scans found three such gaps in succession — root
// devDependencies, then peerDependencies — each invisible to fixtures and each
// stranding an entire subtree. Reporting the count makes the next gap announce
// itself rather than waiting to be noticed (Decision D-18).
func (g *Graph) Orphans() []*Node {
	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	reachable := map[string]bool{}
	for _, e := range g.Edges {
		if e.Type == EdgeDependsOn {
			reachable[e.To] = true
		}
	}
	var out []*Node
	for _, n := range g.SortedNodes() {
		if n.Kind == KindPackage && !roots[n.ID] && !reachable[n.ID] {
			out = append(out, n)
		}
	}
	return out
}

// CountByKind tallies nodes per kind — useful for summaries.
func (g *Graph) CountByKind() map[NodeKind]int {
	m := make(map[NodeKind]int)
	for _, n := range g.Nodes {
		m[n.Kind]++
	}
	return m
}
