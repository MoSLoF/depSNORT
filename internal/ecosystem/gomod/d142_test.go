package gomod

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/securefs"
)

// D-142: maxGoFiles stopped the source walk with a bare return and recorded
// nothing, while its own comment claimed "hitting it is disclosed as a gap, not
// a silent truncation". A documented-but-unimplemented disclosure is worse than
// an undocumented one: a reader checking the code's comment concludes it is
// handled. It now records a GapTruncated.

func d142Module(t *testing.T, nFiles int) string {
	t.Helper()
	dir := t.TempDir()
	for i := 0; i < nFiles; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%d.go", i))
		if err := os.WriteFile(p, []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func d142Collect(t *testing.T, dir string) (int, []instsurf.Gap) {
	t.Helper()
	reader, err := securefs.NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	var gaps instsurf.Gaps
	sources := collectGoSourcesUnder(reader, ".", baseSkipDirRel, &gaps, "pkg:golang/mod@v1")
	return len(sources), gaps.List()
}

func d142Truncations(gaps []instsurf.Gap) []instsurf.Gap {
	var out []instsurf.Gap
	for _, g := range gaps {
		if g.Reason == instsurf.GapTruncated {
			out = append(out, g)
		}
	}
	return out
}

// TestD142GoFileCapIsDisclosed: exceeding the cap must record a gap naming it.
func TestD142GoFileCapIsDisclosed(t *testing.T) {
	n, gaps := d142Collect(t, d142Module(t, maxGoFiles+50))
	if n != maxGoFiles {
		t.Fatalf("expected the cap to bound collection to %d, got %d", maxGoFiles, n)
	}
	tr := d142Truncations(gaps)
	if len(tr) != 1 {
		t.Fatalf("expected exactly one truncation gap, got %d: %v", len(tr), gaps)
	}
	if !strings.Contains(tr[0].Detail, "capped at") {
		t.Errorf("gap detail should name the bound, got %q", tr[0].Detail)
	}
}

// TestD142ExactCapIsNotTruncation is the false-positive boundary, the same one
// D-138 turned on: a module with EXACTLY the cap's worth of files was read in
// full, so reporting it as truncated would attach a coverage gap to a module
// whose surface is completely known.
func TestD142ExactCapIsNotTruncation(t *testing.T) {
	n, gaps := d142Collect(t, d142Module(t, maxGoFiles))
	if n != maxGoFiles {
		t.Fatalf("expected all %d files, got %d", maxGoFiles, n)
	}
	if tr := d142Truncations(gaps); len(tr) != 0 {
		t.Errorf("exactly-at-cap is complete coverage, not truncation; got %v", tr)
	}
}

// TestD142TrailingNonGoFileIsNotTruncation pins a false positive the first cut
// of D-142 actually had: the bound was checked at the top of the entry loop,
// before the .go filter, so a module holding exactly maxGoFiles sources plus any
// other file — a README, a testdata fixture — reported truncation for material
// it was never going to read. Nothing was dropped; the gap was a lie.
func TestD142TrailingNonGoFileIsNotTruncation(t *testing.T) {
	dir := d142Module(t, maxGoFiles)
	// "zz" sorts after every "fN.go", so it is the entry the loop reaches once
	// the count is already at the bound.
	if err := os.WriteFile(filepath.Join(dir, "zz-README.md"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, gaps := d142Collect(t, dir)
	if n != maxGoFiles {
		t.Fatalf("expected all %d sources, got %d", maxGoFiles, n)
	}
	if tr := d142Truncations(gaps); len(tr) != 0 {
		t.Errorf("a non-Go file past the bound is not dropped material; got %v", tr)
	}
}

// TestD142UnenumeratedSubtreeIsTruncation is the other side of that line: a
// directory the walk never opened is unexamined, not known-empty, so it IS
// disclosed even though we cannot say whether it held sources.
func TestD142UnenumeratedSubtreeIsTruncation(t *testing.T) {
	dir := d142Module(t, maxGoFiles)
	sub := filepath.Join(dir, "zz-sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, gaps := d142Collect(t, dir)
	if tr := d142Truncations(gaps); len(tr) != 1 {
		t.Errorf("an unread subtree must be disclosed, got %v", gaps)
	}
}

// TestD142OrdinaryModuleDisclosesNothing: the bound is unreachable for real
// modules, so an ordinary one must carry no truncation gap.
func TestD142OrdinaryModuleDisclosesNothing(t *testing.T) {
	_, gaps := d142Collect(t, d142Module(t, 12))
	if tr := d142Truncations(gaps); len(tr) != 0 {
		t.Errorf("did not expect a truncation gap for an ordinary module, got %v", tr)
	}
}
