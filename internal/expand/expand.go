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
// # Reaching depth N without inventing facts
//
// A node with no version has no coordinate, so a name-only walk stops one layer
// past each pinned package. Stopping there defeats the tool: the layers an
// attacker prefers you never read are exactly the ones below the first.
//
// The way through is not to choose between depth and honesty. It is to record
// HOW EACH VERSION IS KNOWN, and let every downstream stage read that. This
// codebase already separates risk from gate (D-05/D-06), risk from coverage
// (D-24), and origin from verifiability (D-41); the version is the axis that
// was still being treated as uniformly true. See VersionTruth below.
//
// The walk continues through presumed versions, so depth N is reached. What
// changes is what may be CONCLUDED from a node: a finding on a presumed node is
// advisory and never gates, the same structural guarantee D-06 gives proximity
// — high recall in the report, high precision at the gate.
//
// # Why presuming is not the resolver D-01 refused
//
// Presuming is "the highest published version satisfying the accumulated
// constraints". That is a filter and a sort, not a solver: no backtracking, no
// environment-marker evaluation, no conflict search. It is also what pip, npm,
// and cargo actually do in the absence of a conflict, which is the common case
// — so it is right most of the time and wrong in a knowable direction.
//
// When the accumulated constraints admit NOTHING, the walk does not pick a
// side. The node is marked contested, keeps no version, and the walk stops
// there. Declining to conclude when the answer is undetermined is the D-40
// rule (VC-010 refuses when a baseline holds several candidates), applied to
// versions.
package expand

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// Facts recorded by the walk. Ecosystem-neutral, for the reason the coverage
// (D-24) and provenance (D-41) keys are: the verdict layer reads them without
// knowing which registry answered.
const (
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
	Constraint string // raw; parsed only by the owning ecosystem
	Optional   bool   // extras-gated, dev-only, or platform-conditional
}

// Declarer is the per-ecosystem seam. It answers what a coordinate declares and
// owns its own naming rules.
//
// This plus the optional interfaces below is the entire per-ecosystem surface.
// Traversal, per-root containment, dedupe, constraint accumulation, depth
// bounding, and frontier accounting are shared, which is why the walk belongs
// to the engine and not to six adapters.
type Declarer interface {
	// Ecosystem matches graph.Node.Ecosystem.
	Ecosystem() string

	// Identify turns a declared name into this ecosystem's canonical identity
	// for a given version ("" for none), plus the canonical name.
	//
	// IDENTITY NORMALIZATION LIVES HERE. PyPI must fold per PEP 503 and NuGet
	// must lowercase before a name becomes a node, or Flask_SQLAlchemy and
	// flask-sqlalchemy become two nodes and the dedupe below silently fails —
	// the leak D-15 found and closed once already.
	Identify(name, version string) (id, canonicalName string)

	// Declared returns what each coordinate declares, keyed by Coord.Key().
	// A coordinate ABSENT from the map was not read — distinct from one present
	// with an empty slice, which declares nothing. The walk counts the two
	// differently and must never conflate them.
	Declared(ctx context.Context, coords []datasource.Coord) (map[string][]Declaration, error)
}

// VersionIndex lists a package's published versions. Optional: without it the
// walk is name-only and stops at the first unversioned layer.
//
// The registry clients behind VC-004/VC-005 already fetch exactly this data for
// publish-time history, so this is a shape the datasource layer holds today.
type VersionIndex interface {
	// Versions lists published versions, in any order. An error or an empty
	// list leaves the node unversioned rather than presuming from nothing.
	Versions(ctx context.Context, ecosystem, name string) ([]string, error)
}

// Presumer supplies version SEMANTICS. Optional, and required alongside a
// VersionIndex for the walk to presume anything.
//
// Kept per-ecosystem because the semantics genuinely differ — PEP 440 is not
// semver, and Cargo's caret is not npm's. Kept OUT of the engine for the same
// reason Identify is: a shared switch over six grammars is where the drift
// starts. Kept out of Declarer because an ecosystem may be able to report
// declarations long before anyone writes its range grammar, and should not be
// blocked on it.
type Presumer interface {
	// Satisfies reports whether version meets constraint, and whether the
	// constraint could be evaluated AT ALL. An unevaluable constraint yields
	// (false, false) and makes the node contested — never silently unsatisfied,
	// which would read as a deliberate exclusion.
	Satisfies(constraint, version string) (ok, evaluable bool)
	// CompareVersions orders two versions (-1, 0, 1), so the engine can take
	// the highest satisfying candidate without knowing the grammar.
	CompareVersions(a, b string) int
}

// LowestResolver is an optional refinement of Presumer: an ecosystem whose
// installer picks the LOWEST version satisfying a constraint rather than the
// highest. NuGet does this — "1.0" means "the lowest published version >= 1.0",
// not the newest — so a walk that presumed the highest would model a restore
// no NuGet client performs. npm, PyPI, and Cargo take the highest and do not
// implement this; the walk defaults to highest.
type LowestResolver interface {
	Presumer
	// PrefersLowest reports true to select the lowest satisfying candidate.
	PrefersLowest() bool
}

// Options bound the walk.
type Options struct {
	// MaxDepth stops expansion beyond this distance from the root. Zero means
	// the default below. A bound is mandatory, not defensive: past the first
	// layer this walks a graph the operator does not control.
	MaxDepth int
	// IncludeOptional expands extras-gated and platform-conditional
	// declarations. Off by default: they declare what MIGHT be installed, and
	// treating them as present inflates the tree with packages no build fetches.
	IncludeOptional bool
	// NoPresume forces name-only expansion even when a VersionIndex and
	// Presumer are available — the strictest posture, for an operator who wants
	// nothing in the graph that a file did not state.
	NoPresume bool
	// Resolver, when set, supplies the asserted tier (deps.dev). It is queried
	// per registry-queryable DIRECT dependency once that dependency has a
	// coordinate — observed from a lockfile, or the version the seed phase
	// presumes for a manifest-declared dep. It is never handed the local project
	// root, which has no registry coordinate; that mis-target is what left the
	// tier unreachable (OPU-06). A resolved dependency's whole subtree is merged
	// as asserted and closed, so the presume walk never re-derives it.
	Resolver Resolver
}

const defaultMaxDepth = 8

// Result is what one walk learned, per root.
type Result struct {
	Root string `json:"root"`
	// Discovered is how many nodes exist now that did not before.
	Discovered int `json:"discovered"`
	// Presumed is how many of those carry a version this tool chose. The number
	// that bounds what the scan may claim.
	Presumed int `json:"presumed"`
	// Asserted is how many nodes were added with a version a resolver (deps.dev)
	// supplied, rather than one this tool presumed. Disjoint from Discovered so
	// the two tiers are counted, and reported, separately.
	Asserted int `json:"asserted"`
	// Contested is how many had constraints admitting no version, or none that
	// could be evaluated.
	Contested int `json:"contested"`
	// Linked is how many declarations matched a package already in this root's
	// subtree, drawing an edge instead of creating a node.
	Linked int `json:"linked"`
	// Frontier is how many nodes the walk stopped at without reading their
	// dependencies. Everything beneath these is unseen.
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
	index     VersionIndex
}

// NewWalker builds a walker over the given declarers. Without WithVersionIndex
// it is name-only.
func NewWalker(declarers ...Declarer) *Walker {
	m := make(map[string]Declarer, len(declarers))
	for _, d := range declarers {
		m[d.Ecosystem()] = d
	}
	return &Walker{declarers: m}
}

// WithVersionIndex sets a FALLBACK version index, used only for a declarer that
// does not index its own versions. A WalkSource that implements VersionIndex
// itself (both the npm and PyPI ones do) is preferred per-ecosystem, so a
// multi-ecosystem walk needs no global index at all.
func (w *Walker) WithVersionIndex(ix VersionIndex) *Walker {
	cp := *w
	cp.index = ix
	return &cp
}

// pending is one declared package awaiting node creation, with every constraint
// its parents in this layer placed on it.
type pending struct {
	eco          string
	canonical    string
	constraints  []string
	parents      []string
	discoveredBy string
	// depth is one past the DEEPEST parent that declared it. Taken from the
	// parents rather than the loop counter: the initial frontier is every
	// versioned node in the subtree, at mixed depths, so a counter would flatten
	// a layer-3 package's children to layer 1.
	depth int
}

// ExpandRoot walks one root's subtree and no other.
//
// # Per-root containment
//
// The scoping is asymmetric on purpose:
//
//   - MATCHING a declaration against an existing package is restricted to nodes
//     REACHABLE FROM THIS ROOT. Attaching root A's declaration to root B's
//     pinned version infers A's tree from B's file — the inference
//     pypi.ReconstructDepth refuses — and produces an edge indistinguishable
//     from a real one.
//   - CREATING a node is by canonical identity, graph-wide. Two roots that both
//     declare requests share one node with an edge from each, the dedupe this
//     graph performs everywhere, asserting nothing about either.
//
// Never borrow another root's facts; always share the same package's identity.
func (w *Walker) ExpandRoot(ctx context.Context, g *graph.Graph, root *graph.Node, opts Options) (Result, error) {
	res := Result{Root: root.ID}
	if g == nil || root == nil {
		return res, nil
	}
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}

	inSubtree := reachable(g, root.ID)
	byName := map[string]*graph.Node{}
	for id := range inSubtree {
		if n := g.Get(id); n != nil && n.Kind == graph.KindPackage {
			if d := w.declarers[n.Ecosystem]; d != nil {
				_, canon := d.Identify(n.Name, n.Version)
				byName[n.Ecosystem+"|"+canon] = n
			}
		}
	}

	expanded := map[string]bool{}
	var frontier []*graph.Node
	for _, n := range g.SortedNodes() {
		if !inSubtree[n.ID] || n.Kind != graph.KindPackage || n.Version == "" || !registryQueryable(n) {
			continue
		}
		// An asserted node's whole subtree came from a resolver that actually
		// ran (AssertRoot). It is a closed frontier — presuming beneath it would
		// re-derive, with a weaker claim, what the resolver already stated.
		if n.VersionTruth() == graph.TruthAsserted {
			continue
		}
		frontier = append(frontier, n)
		if n.Attr[graph.AttrVersionTruth] == "" && n.ID != root.ID {
			setAttr(n, graph.AttrVersionTruth, graph.TruthObserved)
		}
	}

	// Seed phase: a manifest-only root (unpinned requirements.txt, pyproject
	// [project]) declares direct dependencies the lockfile never pinned, so they
	// are not yet nodes and the registry has no record of the LOCAL root to ask.
	// The adapter recorded them on the root (graph.AttrDeclaredDeps); presume a
	// version for each here, creating a depth-1 node that then enters the walk.
	// This is the case transitive expansion exists for and the frontier-only
	// walk missed: without it, an unpinned project expands nothing.
	for _, root0 := range rootsOf(g, root) {
		d := w.declarers[root0.Ecosystem]
		if d == nil {
			continue
		}
		for _, dd := range root0.DeclaredDepsOf() {
			_, canon := d.Identify(dd.Name, "")
			if canon == "" {
				continue
			}
			mk := root0.Ecosystem + "|" + canon
			if byName[mk] != nil {
				g.AddEdge(root0.ID, byName[mk].ID, graph.EdgeDependsOn)
				continue
			}
			p := &pending{eco: root0.Ecosystem, canonical: canon, parents: []string{root0.ID}, depth: root0.Depth + 1}
			if dd.Constraint != "" {
				p.constraints = []string{dd.Constraint}
			}
			version, truth, candidates := w.presume(ctx, d, p, opts)
			id, cn := d.Identify(canon, version)
			if id == "" {
				continue
			}
			child := g.Get(id)
			if child == nil {
				child = g.AddNode(&graph.Node{
					ID: id, Kind: graph.KindPackage, Ecosystem: root0.Ecosystem,
					Name: cn, Version: version, Direct: true, Depth: root0.Depth + 1,
				})
				setAttr(child, graph.AttrVersionTruth, truth)
				setAttr(child, graph.AttrDeclaredConstraint, dd.Constraint)
				if candidates > 0 {
					setAttr(child, graph.AttrVersionCandidates, strconv.Itoa(candidates))
				}
				res.Discovered++
				switch truth {
				case graph.TruthPresumed, graph.TruthAsserted:
					res.Presumed++
				case graph.TruthContested:
					res.Contested++
				}
			}
			g.AddEdge(root0.ID, child.ID, graph.EdgeDependsOn)
			byName[mk] = child
			inSubtree[child.ID] = true
			if child.Depth > res.DepthReached {
				res.DepthReached = child.Depth
			}
			if child.Version != "" && !expanded[child.ID] {
				frontier = append(frontier, child)
			} else if child.Version == "" {
				markFrontier(child)
				res.Frontier++
			}
		}
	}

	// Asserted tier (D-44, OPU-06): every direct dependency now has a coordinate —
	// observed from a lockfile, or presumed just above for a manifest-declared
	// dep. Hand each registry-queryable one to the resolver; its concrete
	// transitive graph is merged as asserted and the dependency is closed, so the
	// presume walk below never re-derives what the resolver already resolved. The
	// local project root is never handed to the resolver — it has no registry
	// coordinate, and doing so is exactly what kept this tier from ever firing.
	if opts.Resolver != nil {
		// Prefer resolving the local main module's WHOLE build list in one shot
		// (LocalRootResolver — gomod) over resolving each direct dependency
		// independently and unioning: the union is a superset of the real build
		// list, the whole-root resolution is exact (OPU-15). Falls back to the
		// per-dependency path when the resolver has no whole-root answer.
		if !w.assertLocalRoot(ctx, g, root, opts.Resolver, inSubtree, expanded, &res) {
			w.assertDirectSubtrees(ctx, g, root, opts.Resolver, byName, inSubtree, expanded, &res)
		}
	}

	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		// PHASE 1 — read this layer's declarations and accumulate, per declared
		// package, every constraint its parents placed on it. Accumulating
		// before presuming is what lets a diamond be answered once, with all of
		// its constraints in hand, instead of once per parent with each answer
		// overwriting the last.
		queue := map[string]*pending{}
		var order []string

		byEco := map[string][]*graph.Node{}
		var ecos []string
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

		for _, eco := range ecos {
			nodes := byEco[eco]
			d := w.declarers[eco]

			coords := make([]datasource.Coord, 0, len(nodes))
			for _, n := range nodes {
				coords = append(coords, datasource.Coord{Ecosystem: eco, Name: n.Name, Version: n.Version})
			}
			declared, err := d.Declared(ctx, coords)
			if err != nil {
				// A failed fetch bounds the walk by the network, not by the
				// tree, and every node in the batch stays a frontier.
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
					// Absent means never read. Conflating that with "declares
					// nothing" turns an unfetched package into a confident leaf
					// — reporting success because the call ran (the D-42
					// pattern), not because it answered.
					markFrontier(n)
					res.Frontier++
					res.Unread++
					continue
				}
				for _, decl := range decls {
					if decl.Optional && !opts.IncludeOptional {
						continue
					}
					_, canon := d.Identify(decl.Name, "")
					if canon == "" {
						continue
					}
					// Match within this root's subtree only.
					if existing := byName[eco+"|"+canon]; existing != nil {
						g.AddEdge(n.ID, existing.ID, graph.EdgeDependsOn)
						res.Linked++
						continue
					}
					mk := eco + "|" + canon
					p := queue[mk]
					if p == nil {
						p = &pending{eco: eco, canonical: canon, discoveredBy: key}
						queue[mk] = p
						order = append(order, mk)
					}
					if decl.Constraint != "" {
						p.constraints = append(p.constraints, decl.Constraint)
					}
					p.parents = append(p.parents, n.ID)
					if n.Depth+1 > p.depth {
						p.depth = n.Depth + 1
					}
				}
			}
		}

		// PHASE 2 — presume a version for each newly declared package, then
		// create it. Presuming BEFORE creation matters: a node's ID carries its
		// version, so deciding after the fact would mean rewriting an identity
		// that edges already point at.
		var next []*graph.Node
		sort.Strings(order)
		for _, mk := range order {
			p := queue[mk]
			d := w.declarers[p.eco]

			version, truth, candidates := w.presume(ctx, d, p, opts)
			id, canon := d.Identify(p.canonical, version)
			if id == "" {
				continue
			}

			child := g.Get(id)
			if child == nil {
				child = g.AddNode(&graph.Node{
					ID: id, Kind: graph.KindPackage, Ecosystem: p.eco,
					Name: canon, Version: version, Depth: p.depth,
				})
				setAttr(child, graph.AttrVersionTruth, truth)
				setAttr(child, AttrDiscoveredBy, p.discoveredBy)
				setAttr(child, graph.AttrDeclaredConstraint, joinConstraints(p.constraints))
				if candidates > 0 {
					setAttr(child, graph.AttrVersionCandidates, strconv.Itoa(candidates))
				}
				res.Discovered++
				switch truth {
				case graph.TruthPresumed, graph.TruthAsserted:
					res.Presumed++
				case graph.TruthContested:
					res.Contested++
				}
			}
			for _, parent := range p.parents {
				g.AddEdge(parent, child.ID, graph.EdgeDependsOn)
			}
			byName[mk] = child
			inSubtree[child.ID] = true
			if child.Depth > res.DepthReached {
				res.DepthReached = child.Depth
			}

			// The walk continues only through a node that has a coordinate.
			if child.Version != "" && !expanded[child.ID] {
				next = append(next, child)
			} else if child.Version == "" {
				markFrontier(child)
				res.Frontier++
			}
		}
		frontier = next
	}

	// Anything still queued when the depth bound hit is a frontier too: a limit
	// we imposed is disclosed exactly like a limit the data imposed.
	for _, n := range frontier {
		markFrontier(n)
		res.Frontier++
	}
	return res, nil
}

// presume picks the highest published version satisfying every accumulated
// constraint. It is a filter and a sort — no backtracking, no marker
// evaluation, no conflict search — which is why it is not the resolver D-01
// refused, and why it is honest to label its output rather than assert it.
func (w *Walker) presume(ctx context.Context, d Declarer, p *pending, opts Options) (version, truth string, candidates int) {
	pr, canPresume := d.(Presumer)
	// A declarer that also indexes its own versions serves per-ecosystem; the
	// walker's global index is a fallback for a declarer that does not. This is
	// what lets one walk span several ecosystems, each with its own client and
	// its own version grammar, without a shared switch.
	ix, hasIx := d.(VersionIndex)
	if !hasIx {
		ix = w.index
	}
	if opts.NoPresume || ix == nil || !canPresume {
		return "", "", 0 // name-only: no version, and no claim about why
	}

	all, err := ix.Versions(ctx, p.eco, p.canonical)
	if err != nil || len(all) == 0 {
		// Nothing published, or the index could not be read. Either way there
		// is nothing to presume FROM, which is not the same as a constraint
		// that excludes everything — so this is not contested, it is unknown.
		return "", "", 0
	}

	var ok []string
	for _, v := range all {
		fits := true
		for _, c := range p.constraints {
			sat, evaluable := pr.Satisfies(c, v)
			if !evaluable {
				// An unevaluable constraint is not a satisfied one and not a
				// violated one. Guessing either way would be a conclusion drawn
				// from a grammar this tool does not read.
				return "", graph.TruthContested, 0
			}
			if !sat {
				fits = false
				break
			}
		}
		if fits {
			ok = append(ok, v)
		}
	}
	if len(ok) == 0 {
		// Constraints that admit nothing. Real: two parents pinning
		// incompatible ranges. The walk does not pick a side.
		return "", graph.TruthContested, 0
	}
	// Selection direction is the installer's, not a universal. Most resolvers
	// take the highest satisfying version; NuGet takes the lowest. An ecosystem
	// says which by implementing LowestResolver; the default is highest.
	lowest := false
	if lr, ok := d.(LowestResolver); ok {
		lowest = lr.PrefersLowest()
	}
	sort.Slice(ok, func(i, j int) bool {
		c := pr.CompareVersions(ok[i], ok[j])
		if lowest {
			return c < 0
		}
		return c > 0
	})
	return ok[0], graph.TruthPresumed, len(ok)
}

// registryQueryable reports whether it is meaningful to ask a package registry
// what this node depends on. A node whose origin the lockfile recorded as git,
// path, or url (D-41) has no registry coordinate, so querying the registry by
// its name would answer with a DIFFERENT package that happens to share the name
// — grafting a real crate's dependency tree onto a local fork, which is exactly
// the name-confusion the source class exists to prevent. Registry origins and
// UNQUALIFIED nodes (the common case: D-43 qualifies only non-registry origins,
// so an ordinary registry package carries no source attribute) are queryable; a
// node explicitly marked non-registry is not.
func registryQueryable(n *graph.Node) bool {
	class, _ := n.SourceOf()
	return class == graph.SourceRegistry || class == graph.SourceUnknown
}

// assertDirectSubtrees resolves each registry-queryable DIRECT dependency of the
// root through the resolver and merges the concrete transitive graph it returns
// as asserted nodes. A dependency the resolver answers for is then closed —
// marked expanded so the presume walk does not re-derive its subtree with a
// weaker claim — and its new nodes are folded into the walk's containment
// (inSubtree) and dedupe (byName) index so a sibling that shares one links to it
// rather than presuming a second copy.
//
// It is deliberately handed the direct dependencies, not the project root: the
// root is the operator's own local project (path origin, D-41), which has no
// registry coordinate the resolver could ever answer for. Aiming the resolver at
// the root instead of its deps is what made the asserted tier a no-op (OPU-06).
func (w *Walker) assertDirectSubtrees(ctx context.Context, g *graph.Graph, root *graph.Node, r Resolver,
	byName map[string]*graph.Node, inSubtree, expanded map[string]bool, res *Result) {

	var deps []*graph.Node
	seen := map[string]bool{}
	for _, root0 := range rootsOf(g, root) {
		for _, id := range directDepIDs(g, root0.ID) {
			if seen[id] {
				continue
			}
			seen[id] = true
			n := g.Get(id)
			if n == nil || n.Kind != graph.KindPackage || n.Version == "" || !registryQueryable(n) {
				continue
			}
			// Already resolved by a lockfile or an earlier assert — nothing to add.
			if n.VersionTruth() == graph.TruthAsserted {
				continue
			}
			deps = append(deps, n)
		}
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].ID < deps[j].ID }) // determinism (D-13)

	for _, dep := range deps {
		ar, err := w.AssertRoot(ctx, g, dep, r)
		// Fold an unread hole into coverage even when nothing else was asserted: a
		// dependency whose subtree could not be read is still a visible gap (OPU-17).
		res.Unread += ar.Unread
		if err != nil || !ar.Resolved || ar.Asserted == 0 {
			continue
		}
		res.Asserted += ar.Asserted
		// The resolver returned dep's COMPLETE subtree; do not presume beneath it.
		expanded[dep.ID] = true
		// Fold the freshly-asserted nodes into this walk's view so later frontier
		// links resolve to them. Observed/presumed nodes already indexed win —
		// only fill a name that has no node yet (asserted is the weaker claim).
		for id := range reachable(g, dep.ID) {
			inSubtree[id] = true
			cn := g.Get(id)
			if cn == nil || cn.Kind != graph.KindPackage {
				continue
			}
			d := w.declarers[cn.Ecosystem]
			if d == nil {
				continue
			}
			if _, canon := d.Identify(cn.Name, cn.Version); canon != "" {
				if _, ok := byName[cn.Ecosystem+"|"+canon]; !ok {
					byName[cn.Ecosystem+"|"+canon] = cn
				}
			}
		}
	}
}

// directDepIDs returns the ids a node depends on directly, in graph edge order.
func directDepIDs(g *graph.Graph, id string) []string {
	var out []string
	for _, e := range g.SortedEdges() {
		if e.Type == graph.EdgeDependsOn && e.From == id {
			out = append(out, e.To)
		}
	}
	return out
}

// rootsOf returns the seed roots for a single ExpandRoot call. Today that is the
// one root passed in; it is a function so the seed phase reads the same whether
// or not a future change seeds several.
func rootsOf(g *graph.Graph, root *graph.Node) []*graph.Node {
	if root == nil {
		return nil
	}
	return []*graph.Node{root}
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

func joinConstraints(cs []string) string {
	if len(cs) == 0 {
		return ""
	}
	sort.Strings(cs)
	out := cs[0]
	for _, c := range cs[1:] {
		if c != out && !strings.Contains(out, c) {
			out += ", " + c
		}
	}
	return out
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
