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

	// requiresOf caches each module@version's parsed require set for this call;
	// the goproxy client caches the raw fetches across the whole scan. A cached
	// nil means "fetched, not found" so a 404 is not re-requested.
	type reqSet struct {
		reqs []require
		ok   bool
	}
	cache := map[string]reqSet{}
	fetch := func(mod, ver string) ([]require, bool) {
		key := mod + "@" + ver
		if rs, hit := cache[key]; hit {
			return rs.reqs, rs.ok
		}
		raw, ok, err := r.Proxy.ModFile(ctx, mod, ver)
		if err != nil || !ok {
			cache[key] = reqSet{nil, false}
			return nil, false
		}
		_, reqs := scanGoMod(raw)
		cache[key] = reqSet{reqs, true}
		return reqs, true
	}

	// The queried coordinate must resolve, or there is nothing to assert.
	if _, ok := fetch(name, version); !ok {
		return expand.ResolvedGraph{}, false, nil
	}

	// MVS selection: selected[modulePath] = the highest version any reachable
	// module requires. A module path carries its own major-version suffix
	// (foo vs foo/v2), so those are distinct keys by construction.
	//
	// Build the FULL module graph (OPU-14): read the go.mod of every
	// module@version that appears ANYWHERE, not only the version finally selected.
	// A superseded lower version can carry a HIGHER requirement for a third
	// module, and classic (pre-1.17) MVS counts it — reading only selected
	// versions undershoots that third module. Proven on shellz:
	// cloud.google.com/go@v0.52.0 (superseded by v0.54.0, which drops the
	// requirement) is the only requirer of google.golang.org/appengine@v1.6.5, so
	// a selected-only read picked v1.5.0 and the tool would evaluate the wrong
	// artifact for advisories. Reading superseded versions is the correct,
	// conservative direction for a scanner: never evaluate a version LOWER than a
	// real build resolves.
	type coord struct{ mod, ver string }
	selected := map[string]string{name: version}
	graphSeen := map[coord]bool{{name, version}: true}
	work := []coord{{name, version}}
	for len(work) > 0 {
		c := work[len(work)-1]
		work = work[:len(work)-1]
		reqs, ok := fetch(c.mod, c.ver)
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
			if !graphSeen[rc] {
				graphSeen[rc] = true
				work = append(work, rc)
			}
		}
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
		reqs, ok := fetch(m, selected[m])
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

// goVersionLess reports whether a < b under Go's version ordering. semver.Parse
// strips `+incompatible` build metadata (so v3.2.0+incompatible orders as 3.2.0)
// and treats a pseudo-version's timestamp as its prerelease, which sorts
// correctly against another pseudo-version of the same base (14-digit timestamps
// compare lexically as they do numerically) and below any real tag on that base.
func goVersionLess(a, b string) bool {
	return semver.Parse(a).Compare(semver.Parse(b)) < 0
}
