package expand_test

import (
	"context"
	"fmt"
	"testing"

	"ihbv.io/depsnort/internal/expand"
)

// D-143: the walk's depth bound stopped it with packages still queued and said
// nothing a report could read. The leftovers were marked with AttrFrontier —
// an attribute no non-test code in the tree consults — and Result.Frontier,
// which the CLI never folded into anything. A default scan of a tree deeper
// than the bound therefore returned Complete=true over the part it never
// walked. Result.DepthTruncated is the count that makes it sayable, kept apart
// from Frontier because that number conflates this bound with a version that
// would not resolve and a coordinate never fetched.

// d143Chain builds c0 -> c1 -> ... -> cN, one dependency per link.
func d143Chain(n int) *fakePyPI {
	table := map[string][]expand.Declaration{}
	versions := map[string][]string{}
	for i := 0; i < n; i++ {
		table[fmt.Sprintf("pypi|c%d|1.0.0", i)] = []expand.Declaration{{Name: fmt.Sprintf("c%d", i+1)}}
		versions[fmt.Sprintf("c%d", i+1)] = []string{"1.0.0"}
	}
	table[fmt.Sprintf("pypi|c%d|1.0.0", n)] = []expand.Declaration{}
	return &fakePyPI{table: table, versions: versions}
}

func d143Walk(t *testing.T, chain int, opts expand.Options) expand.Result {
	t.Helper()
	d := d143Chain(chain)
	g, root := rootWith(t, map[string]string{"c0": "1.0.0"})
	res, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestD143DepthBoundIsCounted: a chain deeper than the bound leaves work queued,
// and that is the fact a report needs.
func TestD143DepthBoundIsCounted(t *testing.T) {
	res := d143Walk(t, 20, expand.Options{MaxDepth: 4})
	if res.DepthTruncated == 0 {
		t.Fatalf("a 20-deep chain cut at 4 must report truncation; got %+v", res)
	}
}

// TestD143TreeShorterThanBoundIsNotTruncation is the false-positive boundary,
// and the one that matters most here: the bound EXISTS on every walk, so a
// count that fired whenever it was set would mark every ordinary scan
// incomplete and teach operators to ignore the warning.
func TestD143TreeShorterThanBoundIsNotTruncation(t *testing.T) {
	res := d143Walk(t, 2, expand.Options{MaxDepth: 8})
	if res.DepthTruncated != 0 {
		t.Errorf("the walk ran out of tree, not out of depth; got %+v", res)
	}
}

// TestD143ExactlyExhaustedIsNotTruncation pins the tighter edge. Writing it
// wrong first is what established where the edge actually sits: PLACING a node
// is not READING it. A 3-link chain takes 3 layers to put c1..c3 in the graph
// and a 4th to read c3's own declarations, so at MaxDepth=3 the walk really
// does stop with c3 unexamined — truncation, correctly reported. Only at
// MaxDepth=4 has the tree, rather than the bound, ended the walk.
func TestD143ExactlyExhaustedIsNotTruncation(t *testing.T) {
	if res := d143Walk(t, 3, expand.Options{MaxDepth: 3}); res.DepthTruncated != 1 {
		t.Errorf("c3 was placed but never read, which is truncation; got %+v", res)
	}
	if res := d143Walk(t, 3, expand.Options{MaxDepth: 4}); res.DepthTruncated != 0 {
		t.Errorf("one more layer exhausts the chain; got %+v", res)
	}
}

// TestD143DefaultBoundTruncatesSilentlyDeepTrees is the case that made this a
// bug rather than a nicety: no MaxDepth given — what every scan that does not
// pass -expand-depth does — and a tree deeper than the engine's default.
func TestD143DefaultBoundTruncatesDeepTrees(t *testing.T) {
	res := d143Walk(t, 30, expand.Options{})
	if res.DepthTruncated == 0 {
		t.Fatalf("the DEFAULT bound cut a 30-deep chain and reported nothing; got %+v", res)
	}
}
