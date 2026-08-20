package gomod

import (
	"context"
	"testing"
)

// fakeProxy serves canned go.mod text per module@version, with no network.
type fakeProxy map[string]string // "module@version" -> go.mod text

func (f fakeProxy) ModFile(_ context.Context, module, version string) ([]byte, bool, error) {
	if s, ok := f[module+"@"+version]; ok {
		return []byte(s), true, nil
	}
	return nil, false, nil
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
