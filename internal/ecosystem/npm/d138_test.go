package npm

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// D-138: D-137's wildcard resolution stopped at its bounds silently. A bound
// that quietly drops entry modules reports "we looked and found nothing" when
// the truth is "we stopped looking" — the exact invisibility the R-01 gap layer
// exists to prevent, arrived at by a slower route than a planted symlink. Each
// bound now records a GapTruncated coverage gap.

func d138TruncationGaps(gaps []instsurf.Gap) []instsurf.Gap {
	var out []instsurf.Gap
	for _, g := range gaps {
		if g.Reason == instsurf.GapTruncated {
			out = append(out, g)
		}
	}
	return out
}

// TestD138MatchCapDisclosed: exceeding the match cap records a gap naming it.
func TestD138MatchCapDisclosed(t *testing.T) {
	tree := map[string]string{}
	for i := 0; i < maxExportsWildcardMatches*2; i++ {
		tree["src/f"+itoa(i)+".js"] = d137Benign
	}
	got, gaps := d137ResolveWithGaps(t, `{"./s/*": "./src/*.js"}`, tree)
	if len(got) != maxExportsWildcardMatches {
		t.Fatalf("expected the cap to bound results to %d, got %d", maxExportsWildcardMatches, len(got))
	}
	tr := d138TruncationGaps(gaps)
	if len(tr) != 1 {
		t.Fatalf("expected exactly one truncation gap, got %d: %v", len(tr), gaps)
	}
	if !strings.Contains(tr[0].Detail, "match cap") {
		t.Errorf("gap detail should name the bound that tripped, got %q", tr[0].Detail)
	}
	if tr[0].Package != "pkg:npm/wc-pkg@1.0.0" {
		t.Errorf("gap should be attributed to the package node, got %q", tr[0].Package)
	}
}

// TestD138ExactCapIsNotTruncation is the false-positive boundary that matters
// most: a package with EXACTLY the cap's worth of matches was fully examined,
// so it must NOT be reported as truncated. An off-by-one here would attach a
// coverage gap to a package whose surface is completely known.
func TestD138ExactCapIsNotTruncation(t *testing.T) {
	tree := map[string]string{}
	for i := 0; i < maxExportsWildcardMatches; i++ {
		tree["src/f"+itoa(i)+".js"] = d137Benign
	}
	got, gaps := d137ResolveWithGaps(t, `{"./s/*": "./src/*.js"}`, tree)
	if len(got) != maxExportsWildcardMatches {
		t.Fatalf("expected all %d matches, got %d", maxExportsWildcardMatches, len(got))
	}
	if tr := d138TruncationGaps(gaps); len(tr) != 0 {
		t.Errorf("exactly-at-cap is complete coverage, not truncation; got %v", tr)
	}
}

// TestD138OrdinaryPackageDisclosesNothing: the bounds are unreachable for real
// packages, so an ordinary wildcard package must carry no truncation gap.
func TestD138OrdinaryPackageDisclosesNothing(t *testing.T) {
	_, gaps := d137ResolveWithGaps(t, `{"./f/*": "./src/*.js"}`, map[string]string{
		"src/a.js":           d137Benign,
		"src/b.js":           d137Benign,
		"src/deep/nested.js": d137Benign,
	})
	if tr := d138TruncationGaps(gaps); len(tr) != 0 {
		t.Errorf("did not expect a truncation gap for an ordinary package, got %v", tr)
	}
}

// TestD138DepthCapDisclosed: the depth bound is a truncation too — a directory
// past it was never enumerated.
func TestD138DepthCapDisclosed(t *testing.T) {
	deep := "src"
	for i := 0; i <= maxExportsWildcardDepth+2; i++ {
		deep += "/d"
	}
	_, gaps := d137ResolveWithGaps(t, `{"./s/*": "./src/*.js"}`, map[string]string{
		"src/top.js":      d137Benign,
		deep + "/deep.js": d137Benign,
	})
	tr := d138TruncationGaps(gaps)
	if len(tr) != 1 {
		t.Fatalf("expected a truncation gap for the depth bound, got %v", gaps)
	}
	if !strings.Contains(tr[0].Detail, "depth cap") {
		t.Errorf("gap detail should name the depth bound, got %q", tr[0].Detail)
	}
}

// TestD138TruncationSurfacesFromExtractInstallSurface proves the gap reaches
// the caller through the adapter's returned error, which is what the CLI counts
// into ExtractorGaps and reports. A gap recorded but not propagated would be no
// better than the silent stop it replaced.
func TestD138TruncationSurfacesFromExtractInstallSurface(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json",
		`{"name":"wc-pkg","version":"1.0.0","exports":{"./f/*":"./src/*.js"}}`)
	for i := 0; i < maxExportsWildcardMatches*2; i++ {
		writeFile(t, dir, "src/f"+itoa(i)+".js", d137Benign)
	}

	g := graph.New()
	id := "pkg:npm/wc-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "wc-pkg", Version: "1.0.0", Depth: 0,
		Attr: map[string]string{"npm.source": "package.json"},
	})
	g.MarkRoot(id)

	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	if err == nil {
		t.Fatal("expected the truncation to surface as an install-surface gap error")
	}
	found := false
	for _, gp := range instsurf.GapsOf(err) {
		if gp.Reason == instsurf.GapTruncated {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a GapTruncated among %v", instsurf.GapsOf(err))
	}
}
