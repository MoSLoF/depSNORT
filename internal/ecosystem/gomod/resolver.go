package gomod

import (
	"context"
	"sort"

	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/semver"
)

// modFetcher is the slice of the goproxy client the resolver needs: the raw
// go.mod for a module version. A tiny seam so the MVS logic is unit-testable
// without a network (the diamond fixture).
type modFetcher interface {
	ModFile(ctx context.Context, module, version string) ([]byte, bool, error)
}

// Resolver is the Go asserted tier (OPU-13): it resolves a module coordinate's
// full transitive graph from proxy.golang.org — the public, zero-execution
// source `go` itself reads — and applies minimal version selection to choose the
// concrete version of every module. deps.dev cannot serve Go dependency graphs
// (its v3 :dependencies endpoint 404s for every Go coordinate), so Go gets a
// native resolver rather than being routed to a backend that has no answer.
//
// A go.mod's `require` block is static text and MVS is deterministic, so this is
// more aligned with depsnort's charter (D-04 zero-execution, D-09 deterministic,
// offline-capable via the proxy cache) than deps.dev ever was for Go.
type Resolver struct {
	Proxy modFetcher
}

// New builds a Go asserted resolver over a goproxy client (anything providing
// ModFile).
func NewResolver(proxy modFetcher) *Resolver { return &Resolver{Proxy: proxy} }

// Name identifies the source on asserted nodes (AttrAssertedBy) and in coverage.
func (*Resolver) Name() string { return "go-proxy" }

// Resolve returns the MVS-resolved transitive graph for one Go module
// coordinate, or ok=false when the proxy has no record of it (a 404), so the
// walk falls back to presume — the same contract deps.dev's resolver honors.
//
// MVS: the selected version of a module is the MAXIMUM version required by any
// module reachable from the queried coordinate — never the version named on the
// first branch reached. That fixpoint is the actual work, and the reason this is
// a resolver and not a fetch loop: naive recursion mis-versions a module two
// paths require at different versions.
func (r *Resolver) Resolve(ctx context.Context, ecosystem, name, version string) (expand.ResolvedGraph, bool, error) {
	if ecosystem != "gomod" || name == "" || version == "" || r.Proxy == nil {
		return expand.ResolvedGraph{}, false, nil
	}

	// fetch caches each module@version's `go` directive and require set for this
	// call; the goproxy client caches the raw fetches across the whole scan.
	fetch := r.fetcher(ctx, map[string]reqSetOf{})

	// The queried coordinate must resolve, or there is nothing to assert.
	mainGoVer, rootReqs, ok := fetch(name, version)
	if !ok {
		return expand.ResolvedGraph{}, false, nil
	}

	selected := selectBuildList(rootReqs, HasPrunedModuleGraph(mainGoVer), fetch)
	return buildResolvedGraph(name, version, rootReqs, selected, fetch), true, nil
}

// ResolveLocalRoot resolves a LOCAL main module's whole build list from the
// require set the manifest already parsed — its go.mod's `require` block and `go`
// directive — with no proxy coordinate for the root itself. This is the
// OPU-15-exact path: a `depsnort scan` of a local `go 1.17+` main resolves to
// Go's pruned build list (`go list -m all`), not the union of its direct
// dependencies each resolved as if it were its own main module.
//
// The un-seeded Resolve above fetches the root's go.mod from the proxy to learn
// its require set; here the caller supplies it (root.Requires, root.Attr's `go`
// directive), because the local main module has no published version to fetch.
// Everything downstream — MVS, pruning, the flattened graph — is identical, which
// is why the two entry points share selectBuildList and buildResolvedGraph.
func (r *Resolver) ResolveLocalRoot(ctx context.Context, root expand.LocalRoot) (expand.ResolvedGraph, bool, error) {
	if root.Ecosystem != "gomod" || root.Name == "" || r.Proxy == nil || len(root.Requires) == 0 {
		return expand.ResolvedGraph{}, false, nil
	}

	cache := map[string]reqSetOf{}
	fetch := r.fetcher(ctx, cache)

	rootReqs := make([]require, 0, len(root.Requires))
	for _, rr := range root.Requires {
		if rr.Ecosystem != "" && rr.Ecosystem != "gomod" {
			continue
		}
		if rr.Name == "" || rr.Version == "" {
			continue
		}
		rootReqs = append(rootReqs, require{module: rr.Name, version: rr.Version})
	}
	if len(rootReqs) == 0 {
		return expand.ResolvedGraph{}, false, nil
	}

	pruned := HasPrunedModuleGraph(root.Attr[AttrGoDirective])
	selected := selectBuildList(rootReqs, pruned, fetch)
	rootVer := root.Version
	if rootVer == "" {
		rootVer = "0.0.0"
	}
	return buildResolvedGraph(root.Name, rootVer, rootReqs, selected, fetch), true, nil
}

// reqSetOf is one cached go.mod fetch: the `go` directive, the require set, and
// whether the fetch found anything (ok=false is a cached 404).
type reqSetOf struct {
	goVer string
	reqs  []require
	ok    bool
}

// fetcher returns a modFetch backed by the proxy and the given per-call cache. A
// cached ok=false means "fetched, not found" so a 404 is not re-requested.
func (r *Resolver) fetcher(ctx context.Context, cache map[string]reqSetOf) modFetch {
	return func(mod, ver string) (string, []require, bool) {
		key := mod + "@" + ver
		if rs, hit := cache[key]; hit {
			return rs.goVer, rs.reqs, rs.ok
		}
		raw, ok, err := r.Proxy.ModFile(ctx, mod, ver)
		if err != nil || !ok {
			cache[key] = reqSetOf{"", nil, false}
			return "", nil, false
		}
		_, goVer, reqs := scanGoMod(raw)
		cache[key] = reqSetOf{goVer, reqs, true}
		return goVer, reqs, true
	}
}

// selectBuildList runs minimal version selection — pruned (Go 1.17+) or classic
// (pre-1.17) — starting from a main module's require set, and returns
// selected[module]=version for every module in the build list (the root itself
// is not included; the caller places it as node 0).
func selectBuildList(rootReqs []require, pruned bool, fetch modFetch) map[string]string {
	selected := map[string]string{}
	if pruned {
		selectPrunedSeed(rootReqs, selected, fetch)
	} else {
		selectFullGraphSeed(rootReqs, selected, fetch)
	}
	return selected
}

// buildResolvedGraph flattens a build list into a ResolvedGraph: node 0 is the
// root (at rootVer), then every selected module in sorted order (D-13); edges are
// each node → each module it requires that is in the build list. The root's edges
// come from rootReqs (the root may have no fetchable go.mod — a local main
// module); every other node's edges come from its selected version's go.mod.
func buildResolvedGraph(rootName, rootVer string, rootReqs []require, selected map[string]string, fetch modFetch) expand.ResolvedGraph {
	mods := make([]string, 0, len(selected))
	for m := range selected {
		if m != rootName {
			mods = append(mods, m)
		}
	}
	sort.Strings(mods)
	order := append([]string{rootName}, mods...)
	idx := make(map[string]int, len(order))
	nodes := make([]expand.ResolvedRef, len(order))
	for i, m := range order {
		idx[m] = i
		ver := selected[m]
		if i == 0 {
			ver = rootVer
		}
		nodes[i] = expand.ResolvedRef{Ecosystem: "gomod", Name: m, Version: ver}
	}

	var edges []expand.ResolvedEdge
	seen := map[[2]int]bool{}
	addEdges := func(fromIdx int, reqs []require) {
		for _, req := range reqs {
			to, exists := idx[req.module]
			if !exists {
				continue
			}
			e := [2]int{fromIdx, to}
			if e[0] == e[1] || seen[e] {
				continue
			}
			seen[e] = true
			edges = append(edges, expand.ResolvedEdge{From: e[0], To: e[1]})
		}
	}
	addEdges(0, rootReqs)
	for i, m := range order {
		if i == 0 {
			continue
		}
		_, reqs, ok := fetch(m, selected[m])
		if !ok {
			continue
		}
		addEdges(i, reqs)
	}
	return expand.ResolvedGraph{Nodes: nodes, Edges: edges}
}

// modFetch is the go.mod reader the selection passes share: it returns a
// module@version's own `go` directive and require set (ok=false on a 404).
type modFetch func(mod, ver string) (goVer string, reqs []require, ok bool)

// selectFullGraphSeed is classic, unpruned minimal version selection for a main
// module below go 1.17 (OPU-14), seeded from the main module's require set. It
// reads the go.mod of EVERY module@version that appears ANYWHERE in the graph,
// not only the version finally selected: a superseded lower version can carry a
// HIGHER requirement for a third module, and pre-1.17 MVS counts it, so a
// selected-only read undershoots that third module. Proven on shellz:
// cloud.google.com/go@v0.52.0 (superseded by v0.54.0, which drops the
// requirement) is the only requirer of google.golang.org/appengine@v1.6.5 — a
// selected-only read picked v1.5.0 and the tool would evaluate the wrong
// artifact. Reading superseded versions never evaluates a version LOWER than a
// real build resolves.
//
// Seeded, not root-fetching: the caller passes the main module's requires (read
// from the proxy for a published coordinate, or from the local go.mod for a local
// main), so this is identical whether the root is fetchable or not.
func selectFullGraphSeed(rootReqs []require, selected map[string]string, fetch modFetch) {
	type coord struct{ mod, ver string }
	seen := map[coord]bool{}
	var work []coord
	enqueue := func(req require) {
		if cur, exists := selected[req.module]; !exists || goVersionLess(cur, req.version) {
			selected[req.module] = req.version
		}
		// Enqueue THIS exact version — its go.mod is read even when the module is
		// selected higher elsewhere, which is the whole point.
		rc := coord{req.module, req.version}
		if !seen[rc] {
			seen[rc] = true
			work = append(work, rc)
		}
	}
	for _, req := range rootReqs {
		enqueue(req)
	}
	for len(work) > 0 {
		c := work[len(work)-1]
		work = work[:len(work)-1]
		_, reqs, ok := fetch(c.mod, c.ver)
		if !ok {
			continue
		}
		for _, req := range reqs {
			enqueue(req)
		}
	}
}

// selectPrunedSeed reproduces Go 1.17+ module-graph pruning statically (OPU-15)
// for a main module that itself declares go 1.17+. Go prunes such a graph: it
// keeps the full transitive requirements of dependencies at go <= 1.16, but only
// the IMMEDIATE (direct) requirements of dependencies at go 1.17+. A go 1.17+
// main's own go.mod records every module needed to build the main module's
// packages and tests, but the pruned build GRAPH is larger — the extra modules
// come from reading the roots' go.mods under these rules. Walking the full
// unpruned graph instead (selectFullGraphSeed) over-approximates badly:
// opensnitch/daemon (go 1.25)
// resolves to 384 modules unpruned vs Go's 64, selecting versions no real build
// uses (e.g. cloud.google.com/go at the unpruned max instead of Go's v0.26.0).
//
// The pruning is a property of the PATH, not the module alone: once the walk
// enters a go <= 1.16 dependency, that dependency's entire subtree is unpruned —
// including its own transitive go 1.17+ modules. So the walk carries an "unpruned"
// flag that, once set by a go <= 1.16 module, propagates to everything below it.
// A go 1.17+ module reached only through go 1.17+ modules is a frontier: its
// version and its direct requirements count toward the graph, but its
// requirements' requirements are pruned away (never read) unless some go <= 1.16
// module elsewhere pulls them back in.
//
// Seeded from the main module's require set: the main module always expands its
// children (its requires ARE the graph roots), so the seed enqueues each root
// requirement pruned (unpruned=false) — a go <= 1.16 root requirement flips its
// own subtree unpruned when it is read. The main module's own go.mod, being go
// 1.17+, already records the indirect requirements needed to complete the pruned
// graph, so seeding with its full require set and expanding under these rules
// reproduces Go's build list without ever fetching the main module itself.
func selectPrunedSeed(rootReqs []require, selected map[string]string, fetch modFetch) {
	type coord struct{ mod, ver string }
	type item struct {
		c        coord
		unpruned bool // inside a go<=1.16 subtree: expand this module's whole subtree
	}
	// Keyed by (coord, unpruned): a coord first reached as a pruned frontier may
	// later be reached unpruned and must then expand its subtree, so both modes
	// can each run once. Recording a version is idempotent (MVS max), so the only
	// added work is the second expansion, which the frontier case needs.
	seen := map[item]bool{}
	var work []item
	record := func(req require, unpruned bool) {
		// Every immediate requirement of a READ module is a node in the pruned graph
		// and counts toward MVS — including a go1.17+ module's frontier requirements,
		// which Go keeps even though it prunes their subtrees.
		if cur, exists := selected[req.module]; !exists || goVersionLess(cur, req.version) {
			selected[req.module] = req.version
		}
		child := item{coord{req.module, req.version}, unpruned}
		if !seen[child] {
			seen[child] = true
			work = append(work, child)
		}
	}
	for _, req := range rootReqs {
		record(req, false)
	}
	for len(work) > 0 {
		it := work[len(work)-1]
		work = work[:len(work)-1]
		goVer, reqs, ok := fetch(it.c.mod, it.c.ver)
		if !ok {
			continue
		}
		// This module expands its children (reads their go.mods) when it is already
		// inside a go<=1.16 subtree, or when it is itself go<=1.16 (which starts one).
		selfUnpruned := !HasPrunedModuleGraph(goVer)
		expand := it.unpruned || selfUnpruned
		if !expand {
			// A go 1.17+ frontier: its direct requirements still count toward MVS
			// (Go keeps them), but their subtrees are pruned away.
			for _, req := range reqs {
				if cur, exists := selected[req.module]; !exists || goVersionLess(cur, req.version) {
					selected[req.module] = req.version
				}
			}
			continue
		}
		childUnpruned := it.unpruned || selfUnpruned
		for _, req := range reqs {
			record(req, childUnpruned)
		}
	}
}

// goVersionLess reports whether a < b under Go's version ordering. semver.Parse
// strips `+incompatible` build metadata (so v3.2.0+incompatible orders as 3.2.0)
// and treats a pseudo-version's timestamp as its prerelease, which sorts
// correctly against another pseudo-version of the same base (14-digit timestamps
// compare lexically as they do numerically) and below any real tag on that base.
func goVersionLess(a, b string) bool {
	return semver.Parse(a).Compare(semver.Parse(b)) < 0
}
