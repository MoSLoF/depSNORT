// Package expand walks a dependency graph past the last layer the input file
// recorded, using each package's own published metadata.
//
// # The gap this targets
//
// A `requirements.txt` pinning `totallyInnocent==0.11.2` yields exactly one
// resolved package. Whatever totallyInnocent itself depends on — the layer an
// attacker would rather you did not read — is nowhere in the file. D-24 makes
// the scan SAY so (coverage degrades, the banner reads INCOMPLETE); nothing
// closes it.
//
// The fetch that would close it already exists and already runs.
// registry.PyPIDepsClient.RequiresDist pulls a package's declared dependencies
// and reduces each PEP 508 line to a bare name, and cmd/depsnort calls it. But
// its output feeds pypi.ReconstructDepth, which only draws edges BETWEEN
// PACKAGES THAT ARE ALREADY NODES — it re-parents a flat pinned set. Every
// declared name that is not already in the graph is dropped on the floor. That
// dropped set is the missing layer.
//
// # What this package will and will not conclude
//
// A declaration names a package and a CONSTRAINT — `requests>=2.0` — not a
// version. Choosing among the versions a constraint admits is resolution: SAT,
// environment markers, backtracking. D-01 refused to reimplement that and the
// refusal stands.
//
// So a discovered node carries a NAME and a RECORDED CONSTRAINT and NO VERSION.
// It is never given one. A guessed version is indistinguishable from a real one
// once it is in the graph — the DS-REV-02 rule, which cost a Cargo parser its
// correctness when a bare name was widened to an edge, applied one layer up.
//
// # The honest limit
//
// Because a discovered node has no version, it has no coordinate, so its own
// dependencies cannot be fetched. Name-only expansion therefore reaches exactly
// ONE layer past each versioned package — not depth N. Reaching further needs
// versions from somewhere: a resolved-graph service (D-01 named deps.dev), or a
// lockfile that had them all along. That source plugs in as a VersionSource
// below; the walk itself does not change. Nodes where the walk stopped are
// marked, so "how deep did we actually get" stays a reported fact rather than
// an assumption (D-24).
package expand

import (
	"context"
	"sort"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// Facts recorded on discovered nodes. Ecosystem-neutral, for the reason the
// coverage (D-24) and provenance (D-41) keys are: the verdict layer reads them
// without knowing which registry answered.
const (
	// AttrUnversioned marks a node discovered by name from a declaration, with
	// no version ever assigned. Set to "true".
	//
	// Checks MUST branch on this. The name-driven ones — VC-001 (malicious),
	// VC-003 (IOC), VC-006 (typosquat), VC-007 (dependency confusion) — have
	// everything they need. VC-008 (vulnerability) does not: an advisory
	// applies to a version range, and an unversioned node cannot be inside or
	// outside one. It must DECLINE, per the D-15 rule that a check without a
	// basis to judge is silent rather than confident.
	AttrUnversioned = "depsnort.unversioned"
	// AttrDeclaredConstraint is the raw, unevaluated constraint string as the
	// upstream package published it (">=2.0", "^1.2", "~> 3.0"). Recorded
	// verbatim so a reader can see what was claimed without this tool having
	// interpreted it.
	AttrDeclaredConstraint = "depsnort.declared_constraint"
	// AttrDiscoveredBy is the coordinate whose metadata named this package —
	// the evidence for the node existing at all.
	AttrDiscoveredBy = "depsnort.discovered_by"
	// AttrFrontier marks a node where the walk STOPPED: its dependencies were
	// never read, and anything beneath it is unseen. This is what keeps
	// "we walked the tree" from overclaiming.
	AttrFrontier = "depsnort.walk_frontier"
)

// Declaration is one dependency a package declares, unresolved.
type Declaration struct {
	Name       string
	Constraint string // raw; never parsed or evaluated here
	Optional   bool   // extras-gated, dev-only, or platform-conditional
}

// Declarer is the per-ecosystem seam. It answers exactly one question — what
// does this coordinate declare — and owns its own naming rules.
//
// This is the whole per-ecosystem surface of the walk. Everything else in this
// file (traversal, per-root containment, dedupe, cycle handling, frontier
// accounting) is shared, which is why the walk belongs to the engine and not to
// six adapters.
type Declarer interface {
	// Ecosystem matches graph.Node.Ecosystem.
	Ecosystem() string

	// Identify turns a declared name into this ecosystem's canonical
	// unversioned node identity, plus the canonical name.
	//
	// IDENTITY NORMALIZATION LIVES HERE. PyPI must fold per PEP 503 and NuGet
	// must lowercase before a name becomes a node, or `Flask_SQLAlchemy` and
	// `flask-sqlalchemy` become two nodes and the dedupe below silently fails
	// — the exact leak D-15 found and closed once already. Doing it in the
	// shared walk would mean re-deriving six ecosystems' rules in one switch.
	Identify(name string) (id, canonicalName string)

	// Declared returns what each coordinate declares, keyed by Coord.Key().
	// A coordinate ABSENT from the map was not read — distinct from one
	// present with an empty slice, which declares nothing. The walk counts the
	// two differently and must never conflate them.
	Declared(ctx context.Context, coords []datasource.Coord) (map[string][]Declaration, error)
}

// VersionSource is the optional extension that lifts the one-layer limit: given
// a name and a constraint, it supplies a concrete version from an external
// resolved-graph service (D-01's sanctioned path). Absent, the walk is
// name-only and stops at the first unversioned layer.
//
// A version obtained this way is SOMEONE ELSE'S RESOLUTION, not this tool's,
// and the node it produces should record which service asserted it. Deliberately
// not implemented in this sketch — the seam exists so the walk did not have to
// be redesigned around it later.
type VersionSource interface {
	Name() string
	Resolve(ctx context.Context, ecosystem, name, constraint string) (version string, ok bool)
}

// Options bound the walk.
type Options struct {
	// MaxDepth stops expansion beyond this distance from the root. Zero means
	// the default below. A bound is mandatory, not defensive: a walk over
	// published metadata is over a graph this tool does not control.
	MaxDepth int
	// IncludeOptional expands extras-gated and platform-conditional
	// declarations. Off by default: they are declarations of what MIGHT be
	// installed, and treating them as present inflates the tree with packages
	// no build would fetch.
	IncludeOptional bool
}

const defaultMaxDepth = 8

// Result is what one walk learned, per root.
type Result struct {
	// Root is the node the walk started from.
	Root string `json:"root"`
	// Discovered is how many nodes exist now that did not before.
	Discovered int `json:"discovered"`
	// Linked is how many declarations matched a package already in this root's
	// subtree, drawing an edge instead of creating a node.
	Linked int `json:"linked"`
	// Frontier is how many nodes the walk stopped at without reading their
	// dependencies. The headline number: everything beneath these is unseen.
	Frontier int `json:"frontier"`
	// Unread is how many coordinates were submitted for metadata and came back
	// absent — a fetch that did not happen, as distinct from a package that
	// declares nothing.
	Unread int `json:"unread_coordinates"`
	// DepthReached is the greatest depth any node was placed at.
	DepthReached int `json:"depth_reached"`
}

// Walker expands graphs using per-ecosystem declarers.
type Walker struct {
	declarers map[string]Declarer
	versions  VersionSource // optional; nil means name-only
}

// NewWalker builds a walker over the given declarers.
func NewWalker(declarers ...Declarer) *Walker {
	m := make(map[string]Declarer, len(declarers))
	for _, d := range declarers {
		m[d.Ecosystem()] = d
	}
	return &Walker{declarers: m}
}

// WithVersionSource returns a walker that can carry the frontier past the first
// unversioned layer.
func (w *Walker) WithVersionSource(vs VersionSource) *Walker {
	cp := *w
	cp.versions = vs
	return &cp
}

// ExpandRoot walks one root's subtree and no other.
//
// # Per-root containment
//
// The walk is scoped to a single root on purpose, and the scoping is asymmetric
// in a way that matters:
//
//   - MATCHING a declaration against an existing package is restricted to nodes
//     REACHABLE FROM THIS ROOT. Attaching root A's declaration to root B's
//     pinned version would be inferring A's tree from B's file — precisely the
//     inference pypi.ReconstructDepth refuses, and it produces an edge that
//     looks identical to a real one.
//   - CREATING a node is by canonical identity, graph-wide. Two roots that both
//     declare `requests` share one node with an edge from each, which is the
//     dedupe this graph already performs everywhere. Sharing a node both roots
//     genuinely declare asserts nothing about either.
//
// The difference is the whole rule: never borrow another root's FACTS, always
// share the same package's IDENTITY.
func (w *Walker) ExpandRoot(ctx context.Context, g *graph.Graph, root *graph.Node, opts Options) (Result, error) {
	res := Result{Root: root.ID}
	if g == nil || root == nil {
		return res, nil
	}
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}

	// Nodes reachable from this root, by canonical name, for match-not-borrow.
	inSubtree := reachable(g, root.ID)
	byName := map[string]*graph.Node{}
	for id := range inSubtree {
		if n := g.Get(id); n != nil && n.Kind == graph.KindPackage {
			if d := w.declarers[n.Ecosystem]; d != nil {
				_, canon := d.Identify(n.Name)
				byName[n.Ecosystem+"|"+canon] = n
			}
		}
	}

	// Frontier: versioned packages in this subtree we have not yet read.
	expanded := map[string]bool{}
	frontier := make([]*graph.Node, 0, len(inSubtree))
	for _, n := range g.SortedNodes() {
		if inSubtree[n.ID] && n.Kind == graph.KindPackage && n.Version != "" {
			frontier = append(frontier, n)
		}
	}

	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		// Batch per ecosystem so each Declarer sees one call, not one per node.
		byEco := map[string][]*graph.Node{}
		ecos := []string{}
		for _, n := range frontier {
			if expanded[n.ID] || w.declarers[n.Ecosystem] == nil {
				continue
			}
			expanded[n.ID] = true
			if _, seen := byEco[n.Ecosystem]; !seen {
				ecos = append(ecos, n.Ecosystem)
			}
			byEco[n.Ecosystem] = append(byEco[n.Ecosystem], n)
		}
		sort.Strings(ecos) // determinism (D-13)

		var next []*graph.Node
		for _, eco := range ecos {
			nodes := byEco[eco]
			d := w.declarers[eco]

			coords := make([]datasource.Coord, 0, len(nodes))
			for _, n := range nodes {
				coords = append(coords, datasource.Coord{Ecosystem: eco, Name: n.Name, Version: n.Version})
			}
			declared, err := d.Declared(ctx, coords)
			if err != nil {
				// A failed fetch is a gap, not an empty answer: every node in
				// this batch stays a frontier, and the caller learns the walk
				// was bounded by the network rather than by the tree.
				for _, n := range nodes {
					markFrontier(n)
					res.Frontier++
					res.Unread++
				}
				continue
			}

			for _, n := range nodes {
				key := datasource.Coord{Ecosystem: eco, Name: n.Name, Version: n.Version}.Key()
				decls, ok := declared[key]
				if !ok {
					// Absent from the map: never read. Distinct from declaring
					// nothing, and conflating them would turn an unfetched
					// package into a confident leaf.
					markFrontier(n)
					res.Frontier++
					res.Unread++
					continue
				}
				for _, decl := range decls {
					if decl.Optional && !opts.IncludeOptional {
						continue
					}
					id, canon := d.Identify(decl.Name)
					if id == "" || canon == "" {
						continue
					}

					// Match within this root's subtree only.
					if existing := byName[eco+"|"+canon]; existing != nil {
						g.AddEdge(n.ID, existing.ID, graph.EdgeDependsOn)
						res.Linked++
						continue
					}

					child := g.Get(id)
					if child == nil {
						child = g.AddNode(&graph.Node{
							ID:        id,
							Kind:      graph.KindPackage,
							Ecosystem: eco,
							Name:      canon,
							Depth:     n.Depth + 1,
						})
						setAttr(child, AttrUnversioned, "true")
						setAttr(child, AttrDeclaredConstraint, decl.Constraint)
						setAttr(child, AttrDiscoveredBy, key)
						res.Discovered++
					}
					g.AddEdge(n.ID, child.ID, graph.EdgeDependsOn)
					byName[eco+"|"+canon] = child
					inSubtree[child.ID] = true
					if child.Depth > res.DepthReached {
						res.DepthReached = child.Depth
					}

					// The walk continues only through a node with a
					// coordinate. Without a VersionSource that is never a
					// discovered node, and the frontier is where it stops.
					if child.Version != "" && !expanded[child.ID] {
						next = append(next, child)
					} else if child.Version == "" {
						markFrontier(child)
						res.Frontier++
					}
				}
			}
		}
		frontier = next
	}

	// Anything still queued when the depth bound hit is a frontier too: the
	// bound is ours, and a limit we imposed must be disclosed exactly like a
	// limit the data imposed.
	for _, n := range frontier {
		markFrontier(n)
		res.Frontier++
	}
	return res, nil
}

// reachable returns the node IDs reachable from id over declared edges.
func reachable(g *graph.Graph, id string) map[string]bool {
	seen := map[string]bool{id: true}
	queue := []string{id}
	adj := map[string][]string{}
	for _, e := range g.SortedEdges() {
		if e.Type == graph.EdgeDependsOn {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, to := range adj[cur] {
			if !seen[to] {
				seen[to] = true
				queue = append(queue, to)
			}
		}
	}
	return seen
}

func markFrontier(n *graph.Node) { setAttr(n, AttrFrontier, "true") }

func setAttr(n *graph.Node, k, v string) {
	if v == "" {
		return
	}
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	n.Attr[k] = v
}
