package npm

import (
	"encoding/json"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// D-142: D-138 disclosed the wildcard resolver's bounds but left the rest of the
// capped enumerations silent. Two of them are on npm's path: the exports JSON
// walk's depth and entry caps (D-136), and AnalyzeLoadTime's sibling-reference
// cap, whose disclosure is unit-tested in package installsurface where the bound
// is visible. What is tested here is npm's half — the walk's own truncation
// reporting, and that a truncation recorded anywhere in the extractor actually
// reaches the caller as a gap instead of dying in the adapter.

// d142RefsBeyondAnyBound is deliberately far above installsurface's
// maxLoadTimeRefs (16 at the time of writing). It is not a copy of that constant
// — the tests that pin the bound exactly live next to it — only a count large
// enough that the propagation test still exercises truncation if the bound is
// raised. If the bound ever exceeds this, the test below fails loudly rather
// than passing vacuously.
const d142RefsBeyondAnyBound = 64

func d142Trunc(gaps []instsurf.Gap) []instsurf.Gap {
	var out []instsurf.Gap
	for _, g := range gaps {
		if g.Reason == instsurf.GapTruncated {
			out = append(out, g)
		}
	}
	return out
}

func TestD142ExportsDepthCapDisclosed(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 500) + `"./x.js"` + strings.Repeat(`}`, 500)
	tr := exportsTruncation(json.RawMessage(deep))
	if len(tr) == 0 {
		t.Fatal("exceeding the exports depth bound must be disclosed")
	}
	if !strings.Contains(strings.Join(tr, " "), "depth") {
		t.Errorf("disclosure should name the depth bound, got %v", tr)
	}
}

// TestD142ExportsExactDepthIsNotTruncation is the depth bound's false-positive
// boundary: a map whose deepest node sits exactly at the bound was walked to the
// leaf, so nothing is unexamined.
func TestD142ExportsExactDepthIsNotTruncation(t *testing.T) {
	atCap := strings.Repeat(`{"a":`, maxExportsDepth) + `"./x.js"` + strings.Repeat(`}`, maxExportsDepth)
	if tr := exportsTruncation(json.RawMessage(atCap)); len(tr) != 0 {
		t.Errorf("exactly-at-depth is complete coverage, not truncation; got %v", tr)
	}
}

func TestD142ExportsEntryCapDisclosed(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < maxExportsEntries*2; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"./s` + itoa(i) + `":"./f` + itoa(i) + `.js"`)
	}
	b.WriteString("}")
	tr := exportsTruncation(json.RawMessage(b.String()))
	if len(tr) == 0 {
		t.Fatal("exceeding the exports entry bound must be disclosed")
	}
	if !strings.Contains(strings.Join(tr, " "), "capped at") {
		t.Errorf("disclosure should name the bound, got %v", tr)
	}
}

// TestD142ExportsExactEntryCapIsNotTruncation is the false-positive boundary: a
// map holding exactly the cap's worth of entries was walked in full.
func TestD142ExportsExactEntryCapIsNotTruncation(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < maxExportsEntries; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"./s` + itoa(i) + `":"./f` + itoa(i) + `.js"`)
	}
	b.WriteString("}")
	if tr := exportsTruncation(json.RawMessage(b.String())); len(tr) != 0 {
		t.Errorf("exactly-at-cap is complete coverage, not truncation; got %v", tr)
	}
}

// TestD142OrdinaryExportsDisclosesNothing is the shape real packages have: far
// under both bounds, and so carrying no truncation at all.
func TestD142OrdinaryExportsDisclosesNothing(t *testing.T) {
	ordinary := `{".":{"import":"./d/i.mjs","require":"./d/i.cjs"},"./feat":"./d/f.js"}`
	if tr := exportsTruncation(json.RawMessage(ordinary)); len(tr) != 0 {
		t.Errorf("did not expect truncation for an ordinary exports map, got %v", tr)
	}
}

// TestD142ExportsTruncationReachesTheGraph is the exports half of the wiring
// proof. exportsTruncation is a pure function; nothing it computes matters
// unless npmEntryCandidatesResolved actually hands it to the Gaps sink.
func TestD142ExportsTruncationReachesTheGraph(t *testing.T) {
	dir := t.TempDir()
	var ex strings.Builder
	ex.WriteString("{")
	for i := 0; i < maxExportsEntries*2; i++ {
		if i > 0 {
			ex.WriteString(",")
		}
		ex.WriteString(`"./s` + itoa(i) + `":"./f` + itoa(i) + `.js"`)
	}
	ex.WriteString("}")
	writeFile(t, dir, "package.json",
		`{"name":"t","version":"1.0.0","exports":`+ex.String()+`}`)
	writeFile(t, dir, "f0.js", "module.exports={}")

	g := graph.New()
	id := "pkg:npm/t@1.0.0"
	g.AddNode(&graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "t", Version: "1.0.0",
		Attr: map[string]string{"npm.source": "package.json"},
	})
	g.MarkRoot(id)

	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	if err == nil {
		t.Fatal("expected the exports truncation to surface as an install-surface gap")
	}
	tr := d142Trunc(instsurf.GapsOf(err))
	if len(tr) == 0 {
		t.Fatalf("expected a GapTruncated among %v", instsurf.GapsOf(err))
	}
	if !strings.Contains(tr[0].Path, "exports") {
		t.Errorf("gap should point at the exports map, got %q", tr[0].Path)
	}
}

// TestD142TruncationReachesTheGraph proves the disclosure survives the adapter.
// A gap recorded into a sink the caller never sees is no better than the silence
// it replaced, so this drives the real extractor end to end and reads the gap
// off the returned error.
func TestD142TruncationReachesTheGraph(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("const cp = require('child_process');\n")
	for i := 0; i < d142RefsBeyondAnyBound; i++ {
		b.WriteString("require('./mod" + itoa(i) + ".js');\n")
	}
	writeFile(t, dir, "package.json", `{"name":"t","version":"1.0.0","main":"index.js"}`)
	writeFile(t, dir, "index.js", b.String())
	for i := 0; i < d142RefsBeyondAnyBound; i++ {
		writeFile(t, dir, "mod"+itoa(i)+".js", "module.exports={}")
	}

	g := graph.New()
	id := "pkg:npm/t@1.0.0"
	g.AddNode(&graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "t", Version: "1.0.0",
		Attr: map[string]string{"npm.source": "package.json"},
	})
	g.MarkRoot(id)

	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	if err == nil {
		t.Fatalf("expected the truncation to surface as an install-surface gap "+
			"(if the sibling-reference bound was raised above %d, raise this count too)",
			d142RefsBeyondAnyBound)
	}
	if len(d142Trunc(instsurf.GapsOf(err))) == 0 {
		t.Errorf("expected a GapTruncated among %v", instsurf.GapsOf(err))
	}
}
