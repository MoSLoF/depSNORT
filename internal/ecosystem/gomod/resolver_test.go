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
