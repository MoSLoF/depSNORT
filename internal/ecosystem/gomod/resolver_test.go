package gomod

import (
	"context"
	"errors"
	"testing"

	"ihbv.io/depsnort/internal/expand"
)

// fakeProxy serves canned go.mod text per module@version, with no network.
type fakeProxy map[string]string // "module@version" -> go.mod text

func (f fakeProxy) ModFile(_ context.Context, module, version string) ([]byte, bool, error) {
	if s, ok := f[module+"@"+version]; ok {
		return []byte(s), true, nil
	}
	return nil, false, nil
}

// flakyProxy serves canned go.mod text, but a value of the sentinel "ERR" returns
// a TRANSIENT error (err != nil, ok=false) rather than a genuine 404 (ok=false,
// err == nil). This models the goproxy client's outGap vs outNotFound distinction,
// which OPU-17 turns on.
type flakyProxy map[string]string

func (f flakyProxy) ModFile(_ context.Context, module, version string) ([]byte, bool, error) {
	v, ok := f[module+"@"+version]
	if !ok {
		return nil, false, nil // genuine 404
	}
	if v == "ERR" {
		return nil, false, errors.New("go-proxy: connection reset (transient)")
	}
	return []byte(v), true, nil
}

// TestResolverMVSDiamond locks in OPU-13 D-1: when two paths require different
// versions of one module, MVS selects the MAXIMUM, and the resolver reads the
// SELECTED version's go.mod (so a require that only exists at the higher version
// is discovered).
//
//	R ─┬─> A ─> C v1.5.0 ─> D v2.0.0   (D exists only in C@1.5.0)
//	   └─> B ─> C v1.2.0                (C@1.2.0 requires nothing)
//
// Expected build list: A, B, C@v1.5.0 (max), D@v2.0.0. Not C@v1.2.0.
func TestResolverMVSDiamond(t *testing.T) {
	proxy := fakeProxy{
		"R@v1.0.0": "module R\nrequire (\n\tA v1.0.0\n\tB v1.0.0\n)\n",
		"A@v1.0.0": "module A\nrequire C v1.5.0\n",
		"B@v1.0.0": "module B\nrequire C v1.2.0\n",
		"C@v1.5.0": "module C\nrequire D v2.0.0\n",
		"C@v1.2.0": "module C\n",
		"D@v2.0.0": "module D\n",
	}
	r := NewResolver(proxy)
	rg, ok, err := r.Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Resolve ok=%v err=%v", ok, err)
	}
	got := map[string]string{}
	for _, n := range rg.Nodes {
		got[n.Name] = n.Version
	}
	if rg.Nodes[0].Name != "R" {
		t.Errorf("Nodes[0] = %q, want the queried root R", rg.Nodes[0].Name)
	}
	want := map[string]string{"R": "v1.0.0", "A": "v1.0.0", "B": "v1.0.0", "C": "v1.5.0", "D": "v2.0.0"}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("module %s selected %q, want %q", name, got[name], ver)
		}
	}
	if len(got) != len(want) {
		t.Errorf("build list = %v (%d), want %d modules", got, len(got), len(want))
	}
	// D is reachable ONLY because C resolved to v1.5.0 — proves MVS re-reads the
	// selected version's go.mod, not the first version seen.
	if got["D"] != "v2.0.0" {
		t.Error("D missing: resolver did not re-read C at its selected (max) version")
	}

	// Edges must include the resolved require relations (indices into Nodes).
	idx := map[string]int{}
	for i, n := range rg.Nodes {
		idx[n.Name] = i
	}
	wantEdge := func(from, to string) bool {
		for _, e := range rg.Edges {
			if e.From == idx[from] && e.To == idx[to] {
				return true
			}
		}
		return false
	}
	for _, pair := range [][2]string{{"R", "A"}, {"R", "B"}, {"A", "C"}, {"B", "C"}, {"C", "D"}} {
		if !wantEdge(pair[0], pair[1]) {
			t.Errorf("missing edge %s -> %s", pair[0], pair[1])
		}
	}
}

// TestResolverPrunedGraph locks in OPU-15 (D-75): for a main module at go 1.17+,
// Go PRUNES the module graph — a go 1.17+ dependency contributes only its DIRECT
// requirements, while a go <= 1.16 dependency contributes its FULL transitive
// closure (including that closure's own go 1.17+ modules). This is the synthetic
// minimal case that separates correct pruning from both failure modes the OPU-15
// hand-off disproved: go.mod-as-closed (under-selects) and global-max-collapse
// (over-selects a deep requirement Go's pruned graph never reads).
//
//	R (go 1.17) ─┬─> A v1.0.0 (go 1.17) ─> shared v1.0.0 ─> deep v1.0.0
//	             │                                          (A is PRUNED: only its
//	             │                                           direct req `shared` is
//	             │                                           kept; shared's own req
//	             │                                           `deep`, and deep's req,
//	             │                                           are NOT read from A)
//	             └─> B v1.0.0 (go 1.16) ─> shared v2.0.0 ─> deep v3.0.0
//	                                        (B is UNPRUNED: its whole subtree is
//	                                         read — shared v2.0.0 AND deep v3.0.0)
//
// Expected pruned build list: R, A v1.0.0, B v1.0.0, shared v2.0.0, deep v3.0.0.
//   - `shared` = v2.0.0: A requires v1.0.0 (direct, counted) and B's unpruned
//     subtree requires v2.0.0; MVS picks the max, v2.0.0.
//   - `deep` = v3.0.0: reachable ONLY through B's unpruned subtree (via shared
//     v2.0.0). A's pruned edge to shared v1.0.0 is never walked, so shared
//     v1.0.0's `deep v1.0.0` requirement is correctly pruned away — deep's version
//     comes from the unpruned path alone.
func TestResolverPrunedGraph(t *testing.T) {
	proxy := fakeProxy{
		"R@v1.0.0":      "module R\ngo 1.17\nrequire (\n\tA v1.0.0\n\tB v1.0.0\n)\n",
		"A@v1.0.0":      "module A\ngo 1.17\nrequire shared v1.0.0\n",
		"B@v1.0.0":      "module B\ngo 1.16\nrequire shared v2.0.0\n",
		"shared@v1.0.0": "module shared\ngo 1.17\nrequire deep v1.0.0\n",
		"shared@v2.0.0": "module shared\ngo 1.16\nrequire deep v3.0.0\n",
		"deep@v1.0.0":   "module deep\ngo 1.16\n",
		"deep@v3.0.0":   "module deep\ngo 1.16\n",
	}
	rg, ok, err := NewResolver(proxy).Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Resolve ok=%v err=%v", ok, err)
	}
	got := map[string]string{}
	for _, n := range rg.Nodes {
		got[n.Name] = n.Version
	}
	want := map[string]string{"R": "v1.0.0", "A": "v1.0.0", "B": "v1.0.0", "shared": "v2.0.0", "deep": "v3.0.0"}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("module %s selected %q, want %q", name, got[name], ver)
		}
	}
	if len(got) != len(want) {
		t.Errorf("pruned build list = %v (%d modules), want %d", got, len(got), len(want))
	}
	// deep must be v3.0.0 (from B's unpruned subtree), never v1.0.0 (from A's pruned
	// edge, which is not walked). Getting v1.0.0 would mean pruning failed to prune.
	if got["deep"] == "v1.0.0" {
		t.Error("deep is v1.0.0: the resolver walked a PRUNED go 1.17+ subtree it should have cut")
	}
}

// TestResolverPrunedFrontierNotWalked is the tighter half of pruning: a purely
// go 1.17+ chain must be cut at the main module's direct dependency's direct
// requirements. A transitive module reachable ONLY through go 1.17+ modules is
// pruned out of the graph entirely — it is not in `go list -m all`.
//
//	R (go 1.17) ─> A v1.0.0 (go 1.17) ─> B v1.0.0 (go 1.17) ─> C v1.0.0
//
// A is a go 1.17+ direct dep: its direct req B is kept (frontier), but B's req C
// is pruned — C is NOT in the build list. Expected: R, A, B. Not C.
func TestResolverPrunedFrontierNotWalked(t *testing.T) {
	proxy := fakeProxy{
		"R@v1.0.0": "module R\ngo 1.17\nrequire A v1.0.0\n",
		"A@v1.0.0": "module A\ngo 1.17\nrequire B v1.0.0\n",
		"B@v1.0.0": "module B\ngo 1.17\nrequire C v1.0.0\n",
		"C@v1.0.0": "module C\ngo 1.17\n",
	}
	rg, ok, err := NewResolver(proxy).Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Resolve ok=%v err=%v", ok, err)
	}
	got := map[string]bool{}
	for _, n := range rg.Nodes {
		got[n.Name] = true
	}
	if !got["A"] || !got["B"] {
		t.Errorf("build list missing A/B frontier: %v", got)
	}
	if got["C"] {
		t.Error("C is present: a go 1.17+ module's requirement's requirement must be pruned, not walked")
	}
	if len(got) != 3 {
		t.Errorf("pruned build list has %d modules, want 3 (R, A, B)", len(got))
	}
}

// TestResolverQuotedRequirePaths is a parser regression exposed by the OPU-15
// pruning proof against xray-core: the modfile grammar allows a module path or
// version to be a quoted string literal (real modules do this — kr/text@v0.2.0
// writes `require "github.com/creack/pty" v1.1.9`, gopkg.in/yaml.v2 writes
// `require "gopkg.in/check.v1" ...`). Left quoted, the path is a phantom module
// key distinct from its unquoted form, adding a duplicate node at the wrong
// version. The selected version of `q` must merge across the quoted and unquoted
// requirers, and the quoted `"q"` key must never appear.
func TestResolverQuotedRequirePaths(t *testing.T) {
	proxy := fakeProxy{
		"R@v1.0.0": "module R\ngo 1.16\nrequire (\n\tp v1.0.0\n\tu v1.0.0\n)\n",
		"p@v1.0.0": "module \"p\"\ngo 1.16\nrequire \"q\" v1.1.9\n",
		"u@v1.0.0": "module u\ngo 1.16\nrequire q v1.2.0\n",
		"q@v1.1.9": "module q\ngo 1.16\n",
		"q@v1.2.0": "module q\ngo 1.16\n",
	}
	rg, ok, err := NewResolver(proxy).Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Resolve ok=%v err=%v", ok, err)
	}
	got := map[string]string{}
	for _, n := range rg.Nodes {
		got[n.Name] = n.Version
		if n.Name == "\"q\"" || n.Name == "\"p\"" {
			t.Errorf("quoted module path leaked into the graph as a phantom node: %q", n.Name)
		}
	}
	// q required at v1.1.9 (quoted requirer p) and v1.2.0 (unquoted requirer u);
	// MVS over one merged `q` key selects v1.2.0.
	if got["q"] != "v1.2.0" {
		t.Errorf("q selected %q, want v1.2.0 (quoted and unquoted requirers must merge)", got["q"])
	}
	if len(got) != 4 { // R, p, u, q
		t.Errorf("build list = %v (%d), want 4 (R, p, u, q)", got, len(got))
	}
}

// TestResolverUnknownCoordinate: a 404 on the queried coordinate yields ok=false
// so the walk falls back to presume (same contract as deps.dev).
func TestResolverUnknownCoordinate(t *testing.T) {
	r := NewResolver(fakeProxy{})
	if _, ok, _ := r.Resolve(context.Background(), "gomod", "ghost", "v1.0.0"); ok {
		t.Error("an unknown coordinate must resolve ok=false, not fabricate a graph")
	}
	// Wrong ecosystem is declined outright (dispatch routes non-Go elsewhere).
	if _, ok, _ := r.Resolve(context.Background(), "pypi", "flask", "2.0.0"); ok {
		t.Error("the Go resolver must decline a non-gomod ecosystem")
	}
}

// TestResolverMVSReadsSupersededVersions locks in OPU-14: classic MVS reads the
// go.mod of EVERY version in the module graph, not only the selected one. A
// superseded lower version can carry a HIGHER requirement for a third module,
// and that requirement still counts in Go's build list. Reading selected-only
// undershoots it.
//
//	R ─┬─> A v3.0.0 ─> B v1.0.0        (selected A drops the higher B requirement)
//	   └─> C v1.0.0 ─> A v2.0.0 ─> B v2.0.0   (A@v2 SUPERSEDED by A@v3, but its
//	                                            B v2.0.0 requirement still counts)
//
// A is selected at v3.0.0 (max of root's v3 and C's v2). A selected-only read
// picks B v1.0.0 (from A@v3); full-graph MVS reads the superseded A@v2.0.0 too
// and selects B v2.0.0.
func TestResolverMVSReadsSupersededVersions(t *testing.T) {
	proxy := fakeProxy{
		"R@v1.0.0": "module R\nrequire (\n\tA v3.0.0\n\tC v1.0.0\n)\n",
		"C@v1.0.0": "module C\nrequire A v2.0.0\n",
		"A@v3.0.0": "module A\nrequire B v1.0.0\n",
		"A@v2.0.0": "module A\nrequire B v2.0.0\n",
		"B@v1.0.0": "module B\n",
		"B@v2.0.0": "module B\n",
	}
	rg, ok, err := NewResolver(proxy).Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Resolve ok=%v err=%v", ok, err)
	}
	got := map[string]string{}
	for _, n := range rg.Nodes {
		got[n.Name] = n.Version
	}
	if got["A"] != "v3.0.0" {
		t.Errorf("A selected %q, want v3.0.0", got["A"])
	}
	// The heart of OPU-14: B must be v2.0.0, which exists ONLY in the superseded
	// A@v2.0.0's go.mod. A selected-only read would undershoot to v1.0.0.
	if got["B"] != "v2.0.0" {
		t.Errorf("B selected %q, want v2.0.0 (resolver did not read the superseded A@v2.0.0's requirement)", got["B"])
	}
	want := map[string]string{"R": "v1.0.0", "A": "v3.0.0", "C": "v1.0.0", "B": "v2.0.0"}
	if len(got) != len(want) {
		t.Errorf("build list = %v (%d), want %d modules", got, len(got), len(want))
	}
}

// TestResolverUnprunedSubtreeKeeps117Modules isolates the pruning sub-rule the
// other pruning tests miss: once the walk is inside a go<=1.16 dependency's
// UNPRUNED subtree, a go 1.17+ module reached there stays unpruned too — its own
// requirements are kept, not re-pruned for being go 1.17+. TestResolverPrunedGraph
// only places pre-1.17 modules inside the unpruned subtree, so a resolver that
// re-pruned at a 1.17+ node inside an unpruned context would still pass it. This
// test fails loudly on that regression (the `it.unpruned` term in `expand`).
//
//	R (1.20) ─> old v1.0.0 (1.15) ─> modern v1.0.0 (1.19) ─> leaf v1.0.0 (1.19) ─> leafdep v1.0.0
//	             (UNPRUNED: old's whole subtree is kept — the two go 1.19 modules
//	              inside it must ALSO keep expanding, or leafdep is lost)
//
// leafdep is reachable ONLY through the go 1.19 modules inside old's unpruned
// subtree. Correct pruning keeps it; a resolver that re-prunes at a 1.17+ node
// inside an unpruned subtree stops before leafdep.
func TestResolverUnprunedSubtreeKeeps117Modules(t *testing.T) {
	proxy := fakeProxy{
		"R@v1.0.0":       "module R\ngo 1.20\nrequire old v1.0.0\n",
		"old@v1.0.0":     "module old\ngo 1.15\nrequire modern v1.0.0\n",
		"modern@v1.0.0":  "module modern\ngo 1.19\nrequire leaf v1.0.0\n",
		"leaf@v1.0.0":    "module leaf\ngo 1.19\nrequire leafdep v1.0.0\n",
		"leafdep@v1.0.0": "module leafdep\ngo 1.19\n",
	}
	rg, ok, err := NewResolver(proxy).Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Resolve ok=%v err=%v", ok, err)
	}
	got := map[string]bool{}
	for _, n := range rg.Nodes {
		got[n.Name] = true
	}
	// leafdep is the tell: it is reachable only via leaf, which is reached via the
	// go 1.19 module `modern` inside `old`'s go 1.15 unpruned subtree. It survives
	// only if the unpruned flag propagates THROUGH the 1.17+ nodes so they keep
	// expanding. (leaf alone is insufficient: modern records it before the expand
	// check even when broken — the regression only shows one level deeper.)
	if !got["leafdep"] {
		t.Error("leafdep missing: resolver stopped expanding at a go 1.17+ module (modern/leaf) inside a go<=1.16 unpruned subtree — the unpruned flag did not propagate through 1.17+ nodes")
	}
	for _, m := range []string{"R", "old", "modern", "leaf", "leafdep"} {
		if !got[m] {
			t.Errorf("build list missing %s: %v", m, got)
		}
	}
	if len(got) != 5 {
		t.Errorf("build list = %v (%d modules), want 5 (R, old, modern, leaf, leafdep)", got, len(got))
	}
}

// localReqs is a tiny helper: the require set a manifest parses for a local main
// module, in the shape ResolveLocalRoot consumes.
func localReqs(pairs ...[2]string) []expand.ResolvedRef {
	out := make([]expand.ResolvedRef, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, expand.ResolvedRef{Ecosystem: "gomod", Name: p[0], Version: p[1]})
	}
	return out
}

// TestResolveLocalRootCollapsesToOneVersion is the heart of OPU-15-exact: a LOCAL
// main module resolves to Go's build list — ONE version per module — from its own
// require set, WITHOUT a proxy coordinate for the root. The failure mode it guards
// is the per-dependency union: two direct deps that require different versions of
// a shared module. Resolving each dep independently and merging keeps BOTH
// versions (the 170-vs-64 opensnitch inflation); resolving the whole root runs one
// MVS and collapses to the max.
//
//	M ─┬─> A v1.0.0 ─> X v2.0.0
//	   └─> B v1.0.0 ─> X v1.0.0
//
// Whole-root build list: M, A, B, X v2.0.0 (max) — X appears exactly once.
func TestResolveLocalRootCollapsesToOneVersion(t *testing.T) {
	proxy := fakeProxy{
		"A@v1.0.0": "module A\ngo 1.16\nrequire X v2.0.0\n",
		"B@v1.0.0": "module B\ngo 1.16\nrequire X v1.0.0\n",
		"X@v2.0.0": "module X\ngo 1.16\n",
		"X@v1.0.0": "module X\ngo 1.16\n",
	}
	root := expand.LocalRoot{
		Ecosystem: "gomod", Name: "M", Version: "0.0.0",
		Requires: localReqs([2]string{"A", "v1.0.0"}, [2]string{"B", "v1.0.0"}),
		Attr:     map[string]string{}, // no `go` directive → pre-1.17 classic MVS
	}
	rg, ok, err := NewResolver(proxy).ResolveLocalRoot(context.Background(), root)
	if err != nil || !ok {
		t.Fatalf("ResolveLocalRoot ok=%v err=%v", ok, err)
	}
	if rg.Nodes[0].Name != "M" {
		t.Errorf("Nodes[0] = %q, want the seeded root M", rg.Nodes[0].Name)
	}
	got := map[string]string{}
	xCount := 0
	for _, n := range rg.Nodes {
		got[n.Name] = n.Version
		if n.Name == "X" {
			xCount++
		}
	}
	if xCount != 1 {
		t.Errorf("X appears %d times, want exactly 1 (whole-root MVS collapses; the union would keep both versions)", xCount)
	}
	if got["X"] != "v2.0.0" {
		t.Errorf("X selected %q, want v2.0.0 (MVS max over the whole root)", got["X"])
	}
	want := map[string]string{"M": "0.0.0", "A": "v1.0.0", "B": "v1.0.0", "X": "v2.0.0"}
	if len(got) != len(want) {
		t.Errorf("build list = %v (%d), want %d (M, A, B, X)", got, len(got), len(want))
	}
}

// TestResolveLocalRootPrunes proves the go 1.17+ pruning applies through the
// LOCAL-root entry too: a main declaring go 1.17+ prunes a purely go 1.17+ chain
// at its direct dependency's direct requirement, exactly as the queried-coordinate
// path does (TestResolverPrunedFrontierNotWalked), but seeded from the parsed
// require set rather than a fetched root go.mod.
//
//	M (go 1.20) ─> A v1.0.0 (go 1.17) ─> B v1.0.0 (go 1.17) ─> C v1.0.0
//
// A is a go 1.17+ frontier: B is kept, C is pruned. Expected: M, A, B. Not C.
func TestResolveLocalRootPrunes(t *testing.T) {
	proxy := fakeProxy{
		"A@v1.0.0": "module A\ngo 1.17\nrequire B v1.0.0\n",
		"B@v1.0.0": "module B\ngo 1.17\nrequire C v1.0.0\n",
		"C@v1.0.0": "module C\ngo 1.17\n",
	}
	root := expand.LocalRoot{
		Ecosystem: "gomod", Name: "M", Version: "0.0.0",
		Requires: localReqs([2]string{"A", "v1.0.0"}),
		Attr:     map[string]string{AttrGoDirective: "1.20"}, // go 1.17+ → pruned
	}
	rg, ok, err := NewResolver(proxy).ResolveLocalRoot(context.Background(), root)
	if err != nil || !ok {
		t.Fatalf("ResolveLocalRoot ok=%v err=%v", ok, err)
	}
	got := map[string]bool{}
	for _, n := range rg.Nodes {
		got[n.Name] = true
	}
	if !got["A"] || !got["B"] {
		t.Errorf("build list missing A/B frontier: %v", got)
	}
	if got["C"] {
		t.Error("C is present: a go 1.17+ frontier's requirement's requirement must be pruned via the local-root path too")
	}
	if len(got) != 3 {
		t.Errorf("build list = %v, want 3 (M, A, B)", got)
	}
}

// TestResolveLocalRootDeclinesNonGomod: the whole-root path is gomod-only; any
// other ecosystem (or an empty require set) returns ok=false so the walker falls
// back to the per-dependency AssertRoot path.
func TestResolveLocalRootDeclinesNonGomod(t *testing.T) {
	r := NewResolver(fakeProxy{})
	if _, ok, _ := r.ResolveLocalRoot(context.Background(), expand.LocalRoot{
		Ecosystem: "pypi", Name: "app", Requires: localReqs([2]string{"flask", "v1.0.0"}),
	}); ok {
		t.Error("ResolveLocalRoot must decline a non-gomod root")
	}
	if _, ok, _ := r.ResolveLocalRoot(context.Background(), expand.LocalRoot{
		Ecosystem: "gomod", Name: "M",
	}); ok {
		t.Error("ResolveLocalRoot must decline a root with no requires")
	}
}

// asIncomplete returns the *expand.IncompleteResolution an error wraps, or nil.
func asIncomplete(err error) *expand.IncompleteResolution {
	var inc *expand.IncompleteResolution
	if errors.As(err, &inc) {
		return inc
	}
	return nil
}

// TestResolverTransientFetchFailureSignalsIncomplete locks in OPU-17: a TRANSIENT
// go.mod fetch failure (network/transport) must NOT be conflated with a clean
// resolution. The affected module's subtree is unread, so Resolve returns the
// partial graph AND an *IncompleteResolution naming it — never err==nil, which
// would present a silently-shrunk build list as complete.
//
//	R ─> A v1.0.0 (go.mod fetch TRANSIENTLY fails) ─> B v1.0.0 (never reached)
//
// A is in the build list (recorded from R's require before the fetch), but B is
// unknowable — the point is that the incompleteness is REPORTED, not that B is
// recovered.
func TestResolverTransientFetchFailureSignalsIncomplete(t *testing.T) {
	proxy := flakyProxy{
		"R@v1.0.0": "module R\ngo 1.16\nrequire A v1.0.0\n",
		"A@v1.0.0": "ERR", // transient failure fetching A's go.mod
		"B@v1.0.0": "module B\ngo 1.16\n",
	}
	rg, ok, err := NewResolver(proxy).Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if !ok {
		t.Fatal("Resolve returned ok=false; a transient failure below the root must still yield the partial graph")
	}
	inc := asIncomplete(err)
	if inc == nil {
		t.Fatalf("err = %v, want *IncompleteResolution (a transient failure must be signalled, not silent)", err)
	}
	if len(inc.Unread) != 1 || inc.Unread[0].Name != "A" || inc.Unread[0].Version != "v1.0.0" {
		t.Errorf("Unread = %+v, want exactly [A v1.0.0]", inc.Unread)
	}
	names := map[string]bool{}
	for _, n := range rg.Nodes {
		names[n.Name] = true
	}
	if !names["A"] {
		t.Error("A missing: the partial build list should still contain the module that failed")
	}
}

// TestResolver404IsNotIncomplete is the discriminating other half: a GENUINE 404
// (the module truly has no record) is not a transient failure — Resolve returns
// err==nil. Same shrunk graph as the transient case, but honestly a "not found",
// not an "unread". Without this, the fix could cry incomplete on every 404.
func TestResolver404IsNotIncomplete(t *testing.T) {
	proxy := flakyProxy{
		"R@v1.0.0": "module R\ngo 1.16\nrequire A v1.0.0\n",
		// A@v1.0.0 absent entirely -> genuine 404 (ok=false, err==nil).
	}
	_, ok, err := NewResolver(proxy).Resolve(context.Background(), "gomod", "R", "v1.0.0")
	if !ok {
		t.Fatal("Resolve returned ok=false; a 404 below the root must still yield the partial graph")
	}
	if err != nil {
		t.Errorf("err = %v, want nil: a genuine 404 is not an incomplete resolution", err)
	}
}

// TestResolveLocalRootTransientFailureSignalsIncomplete is the same guarantee on
// the OPU-15-exact path (the one a real `depsnort scan` of a local go.mod takes):
// a transient failure while resolving the whole build list must surface as
// *IncompleteResolution, so the scan reports a gap instead of shrinking silently.
func TestResolveLocalRootTransientFailureSignalsIncomplete(t *testing.T) {
	proxy := flakyProxy{
		"A@v1.0.0": "module A\ngo 1.16\nrequire C v1.0.0\n",
		"C@v1.0.0": "ERR", // transient failure deep in the build list
		"D@v1.0.0": "module D\ngo 1.16\n",
	}
	root := expand.LocalRoot{
		Ecosystem: "gomod", Name: "M", Version: "0.0.0",
		Requires: []expand.ResolvedRef{
			{Ecosystem: "gomod", Name: "A", Version: "v1.0.0"},
			{Ecosystem: "gomod", Name: "D", Version: "v1.0.0"},
		},
		Attr: map[string]string{AttrGoDirective: "1.16"},
	}
	_, ok, err := NewResolver(proxy).ResolveLocalRoot(context.Background(), root)
	if !ok {
		t.Fatal("ResolveLocalRoot returned ok=false; a transient failure must still yield the partial build list")
	}
	inc := asIncomplete(err)
	if inc == nil {
		t.Fatalf("err = %v, want *IncompleteResolution", err)
	}
	if len(inc.Unread) != 1 || inc.Unread[0].Name != "C" {
		t.Errorf("Unread = %+v, want exactly [C ...]", inc.Unread)
	}
}
