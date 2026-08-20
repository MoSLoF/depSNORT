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
	// call; the goproxy client caches the raw fetches across the whole scan. A
	// cached ok=false means "fetched, not found" so a 404 is not re-requested.
	type reqSet struct {
		goVer string
		reqs  []require
		ok    bool
	}
	cache := map[string]reqSet{}
	fetch := func(mod, ver string) (string, []require, bool) {
		key := mod + "@" + ver
		if rs, hit := cache[key]; hit {
			return rs.goVer, rs.reqs, rs.ok
		}
		raw, ok, err := r.Proxy.ModFile(ctx, mod, ver)
		if err != nil || !ok {
			cache[key] = reqSet{"", nil, false}
			return "", nil, false
		}
		_, goVer, reqs := scanGoMod(raw)
		cache[key] = reqSet{goVer, reqs, true}
		return goVer, reqs, true
	}

	// The queried coordinate must resolve, or there is nothing to assert.
	mainGoVer, _, ok := fetch(name, version)
	if !ok {
		return expand.ResolvedGraph{}, false, nil
	}

	// MVS selection: selected[modulePath] = the highest version any module in the
	// build graph requires. A module path carries its own major-version suffix
	// (foo vs foo/v2), so those are distinct keys by construction.
	selected := map[string]string{name: version}
	if HasPrunedModuleGraph(mainGoVer) {
		selectPruned(name, version, selected, fetch)
	} else {
		selectFullGraph(name, version, selected, fetch)
	}

	// Flatten: node 0 is the queried root, then modules in sorted order for
	// deterministic output (D-13).
	mods := make([]string, 0, len(selected))
	for m := range selected {
		if m != name {
			mods = append(mods, m)
		}
	}
	sort.Strings(mods)
	order := append([]string{name}, mods...)
	idx := make(map[string]int, len(order))
	nodes := make([]expand.ResolvedRef, len(order))
	for i, m := range order {
		idx[m] = i
		nodes[i] = expand.ResolvedRef{Ecosystem: "gomod", Name: m, Version: selected[m]}
	}

	// Edges: each module (at its selected version) → each module it requires (at
	// the selected version). Deduped; self-loops dropped.
	var edges []expand.ResolvedEdge
	seen := map[[2]int]bool{}
	for _, m := range order {
		_, reqs, ok := fetch(m, selected[m])
		if !ok {
			continue
		}
		for _, req := range reqs {
			to, exists := idx[req.module]
			if !exists {
				continue
			}
			e := [2]int{idx[m], to}
			if e[0] == e[1] || seen[e] {
				continue
			}
			seen[e] = true
			edges = append(edges, expand.ResolvedEdge{From: e[0], To: e[1]})
		}
	}
	return expand.ResolvedGraph{Nodes: nodes, Edges: edges}, true, nil
}

// modFetch is the go.mod reader the selection passes share: it returns a
// module@version's own `go` directive and require set (ok=false on a 404).
type modFetch func(mod, ver string) (goVer string, reqs []require, ok bool)

// selectFullGraph is classic, unpruned minimal version selection for a main
// module below go 1.17 (OPU-14). It reads the go.mod of EVERY module@version
// that appears ANYWHERE in the graph, not only the version finally selected: a
// superseded lower version can carry a HIGHER requirement for a third module,
// and pre-1.17 MVS counts it, so a selected-only read undershoots that third
// module. Proven on shellz: cloud.google.com/go@v0.52.0 (superseded by v0.54.0,
// which drops the requirement) is the only requirer of
// google.golang.org/appengine@v1.6.5 — a selected-only read picked v1.5.0 and
// the tool would evaluate the wrong artifact. Reading superseded versions never
// evaluates a version LOWER than a real build resolves.
func selectFullGraph(name, version string, selected map[string]string, fetch modFetch) {
	type coord struct{ mod, ver string }
	seen := map[coord]bool{{name, version}: true}
	work := []coord{{name, version}}
	for len(work) > 0 {
		c := work[len(work)-1]
		work = work[:len(work)-1]
		_, reqs, ok := fetch(c.mod, c.ver)
		if !ok {
			continue
		}
		for _, req := range reqs {
			if cur, exists := selected[req.module]; !exists || goVersionLess(cur, req.version) {
				selected[req.module] = req.version
			}
			// Enqueue THIS exact version — its go.mod is read even when the module
			// is selected higher elsewhere, which is the whole point.
			rc := coord{req.module, req.version}
			if !seen[rc] {
				seen[rc] = true
				work = append(work, rc)
			}
		}
	}
}

// selectPruned reproduces Go 1.17+ module-graph pruning statically (OPU-15) for a
// main module that itself declares go 1.17+. Go prunes such a graph: it keeps the
// full transitive requirements of dependencies at go <= 1.16, but only the
// IMMEDIATE (direct) requirements of dependencies at go 1.17+. A go 1.17+ main's
// own go.mod records every module needed to build the main module's packages and
// tests, but the pruned build GRAPH is larger — the extra modules come from
// reading the roots' go.mods under these rules. Walking the full unpruned graph
// instead (selectFullGraph) over-approximates badly: opensnitch/daemon (go 1.25)
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
func selectPruned(name, version string, selected map[string]string, fetch modFetch) {
	type coord struct{ mod, ver string }
	type item struct {
		c        coord
		unpruned bool // inside a go<=1.16 subtree: expand this module's whole subtree
	}
	main := coord{name, version}
	// Keyed by (coord, unpruned): a coord first reached as a pruned frontier may
	// later be reached unpruned and must then expand its subtree, so both modes
	// can each run once. Recording a version is idempotent (MVS max), so the only
	// added work is the second expansion, which the frontier case needs.
	seen := map[item]bool{{main, false}: true}
	work := []item{{main, false}}
	for len(work) > 0 {
		it := work[len(work)-1]
		work = work[:len(work)-1]
		goVer, reqs, ok := fetch(it.c.mod, it.c.ver)
		if !ok {
			continue
		}
		// This module expands its children (reads their go.mods) when it is the
		// main module (its requires are the graph roots), when it is already inside
		// a go<=1.16 subtree, or when it is itself go<=1.16 (which starts one).
		selfUnpruned := !HasPrunedModuleGraph(goVer)
		expand := it.c == main || it.unpruned || selfUnpruned
		for _, req := range reqs {
			// Every immediate requirement of a READ module is a node in the pruned
			// graph and counts toward MVS — including a go1.17+ module's frontier
			// requirements, which Go keeps even though it prunes their subtrees.
			if cur, exists := selected[req.module]; !exists || goVersionLess(cur, req.version) {
				selected[req.module] = req.version
			}
			if !expand {
				continue
			}
			childUnpruned := it.unpruned || selfUnpruned
			child := item{coord{req.module, req.version}, childUnpruned}
			if !seen[child] {
				seen[child] = true
				work = append(work, child)
			}
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
