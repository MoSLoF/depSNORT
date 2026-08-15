package pypi

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

func TestDetect(t *testing.T) {
	a := &Adapter{}
	for _, p := range []string{"testdata/realworld", "testdata/pipfile", "testdata/mixed"} {
		if !a.Detect(p) {
			t.Errorf("Detect(%q) = false, want true", p)
		}
	}
	if a.Detect("testdata") {
		t.Error("Detect should not match a dir with no supported input")
	}
}

func TestPEP503Normalization(t *testing.T) {
	cases := map[string]string{
		"Flask_SQLAlchemy":  "flask-sqlalchemy",
		"flask-sqlalchemy":  "flask-sqlalchemy",
		"Flask.SQL_Alchemy": "flask-sql-alchemy",
		"zope..interface":   "zope-interface",
		"REQUESTS":          "requests",
		"typing_extensions": "typing-extensions",
	}
	for in, want := range cases {
		if got := purl.NormalizePyPI(in); got != want {
			t.Errorf("NormalizePyPI(%q) = %q, want %q", in, got, want)
		}
	}
	// The whole point: differently-spelled names collapse to ONE node.
	if purl.NewPyPI("Flask_SQLAlchemy", "2.5.1").String() != purl.NewPyPI("flask-sqlalchemy", "2.5.1").String() {
		t.Error("PEP 503 variants must produce the same PURL")
	}
}

func TestRequirementsEdgesFromViaComments(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/realworld")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// 12 packages + 1 synthetic root.
	if g.Len() != 13 {
		t.Fatalf("nodes = %d, want 13", g.Len())
	}

	// `# via requests` must become a real depends-on edge, not a root child.
	certifi := purl.NewPyPI("certifi", "2018.11.29").String()
	requests := purl.NewPyPI("requests", "2.19.1").String()
	var found bool
	for _, e := range g.Edges {
		if e.From == requests && e.To == certifi && e.Type == graph.EdgeDependsOn {
			found = true
		}
	}
	if !found {
		t.Error("missing requests -> certifi edge reconstructed from '# via'")
	}
	if n := g.Get(certifi); n == nil || n.Depth != 2 {
		t.Errorf("certifi depth = %v, want 2 (transitive)", n)
	}

	// jinja2 has a multi-line via listing BOTH -r and flask: the file reference
	// is ignored, the package reference becomes an edge.
	jinja := purl.NewPyPI("jinja2", "2.10").String()
	flask := purl.NewPyPI("flask", "0.12.2").String()
	var jinjaFromFlask bool
	for _, e := range g.Edges {
		if e.From == flask && e.To == jinja {
			jinjaFromFlask = true
		}
	}
	if !jinjaFromFlask {
		t.Error("missing flask -> jinja2 edge from multi-line via block")
	}

	// flask is `via -r requirements.in` only -> direct dependency of the root.
	if n := g.Get(flask); n == nil || !n.Direct {
		t.Errorf("flask should be a direct dependency: %+v", n)
	}
}

func TestRequirementsPinningAndExtras(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/mixed")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Extras stripped, name normalized. The marker is now captured (not
	// evaluated for a pinned entry — python_version >= "3.8" is not a
	// platform-gate this parser tries to interpret) but must not block
	// resolution of the pin itself.
	n := g.Get(purl.NewPyPI("flask-sqlalchemy", "2.5.1").String())
	if n == nil {
		t.Fatal("Flask_SQLAlchemy[async]==2.5.1 with a marker was not resolved")
	}
	if got := n.Attr["pypi.marker"]; got != `python_version >= "3.8"` {
		t.Errorf(`pypi.marker = %q, want python_version >= "3.8"`, got)
	}
	// Inline --hash must not corrupt the version.
	if n := g.Get(purl.NewPyPI("requests", "2.31.0").String()); n == nil {
		t.Error("requests==2.31.0 with an inline --hash was not resolved")
	}
	// Unpinned specifiers must NOT be resolved (D-01: no range solving)...
	for _, name := range []string{"urllib3", "some-package"} {
		for _, n := range g.SortedNodes() {
			if n.Name == name {
				t.Errorf("unpinned %q was resolved to %q — ranges must not be guessed", name, n.Version)
			}
		}
	}
	// ...but they must be DISCLOSED, not silently dropped.
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root == nil || root.Attr[graph.AttrUnresolvedCount] != "2" {
		t.Errorf("unresolved requirements not disclosed on the root: %+v", root)
	}
}

func TestPipfileLock(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/pipfile")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Len() != 4 { // root + 2 default + 1 develop
		t.Fatalf("nodes = %d, want 4", g.Len())
	}
	n := g.Get(purl.NewPyPI("requests", "2.19.1").String())
	if n == nil {
		t.Fatal("requests not resolved from Pipfile.lock")
	}
	if n.Attr["pypi.section"] != "default" {
		t.Errorf("section = %q, want default", n.Attr["pypi.section"])
	}
	if p := g.Get(purl.NewPyPI("pytest", "7.4.0").String()); p == nil || p.Attr["pypi.section"] != "develop" {
		t.Errorf("develop section not recorded: %+v", p)
	}
}

// A fully pinned requirements.txt with zero `# via` annotations — exactly
// what plain `pip freeze` produces — resolves every package fine but cannot
// reconstruct real edges. That must be disclosed the same way Pipfile.lock's
// flatness is, not silently reported as a genuine dependency tree.
func TestFlatResolutionForProvenanceFreeRequirements(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/pipfreeze")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root == nil || root.Attr[graph.AttrFlatResolution] != "pypi" {
		t.Errorf("provenance-free requirements.txt not flagged flat: %+v", root)
	}
	cov := g.Coverage()
	var found bool
	for _, eco := range cov.FlatEcosystems {
		if eco == "pypi" {
			found = true
		}
	}
	if !found {
		t.Errorf("Coverage().FlatEcosystems = %v, want to include \"pypi\"", cov.FlatEcosystems)
	}
}

// A file that DOES carry `# via` provenance — even a partial listing, like
// testdata/mixed and testdata/realworld — must NOT be flagged flat: the
// format can express structure here and mostly did.
func TestProvenancePresentIsNotFlaggedFlat(t *testing.T) {
	for _, dir := range []string{"testdata/mixed", "testdata/realworld"} {
		g, err := (&Adapter{}).Resolve(dir)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", dir, err)
		}
		var root *graph.Node
		for _, id := range g.Roots {
			root = g.Get(id)
		}
		if root != nil && root.Attr[graph.AttrFlatResolution] != "" {
			t.Errorf("%s: should not be flagged flat, got %q", dir, root.Attr[graph.AttrFlatResolution])
		}
	}
}

// An unpinned dependency gated to Windows only by an unambiguous marker must
// not inflate the unresolved count — but the exclusion itself must be
// disclosed, not silent. A marker this parser cannot prove excludes (e.g. a
// python_version comparison) must still count as unresolved.
func TestMarkerExclusionIsNarrowAndDisclosed(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/markers")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root == nil {
		t.Fatal("root missing")
	}
	if root.Attr["pypi.marker_excluded"] != "pyreadline3" {
		t.Errorf(`pypi.marker_excluded = %q, want "pyreadline3"`, root.Attr["pypi.marker_excluded"])
	}
	if root.Attr[graph.AttrUnresolved] != "some-lib" {
		t.Errorf(`%s = %q, want "some-lib" (pyreadline3 must be excluded, some-lib must not)`, graph.AttrUnresolved, root.Attr[graph.AttrUnresolved])
	}
	if root.Attr[graph.AttrUnresolvedCount] != "1" {
		t.Errorf("%s = %q, want \"1\"", graph.AttrUnresolvedCount, root.Attr[graph.AttrUnresolvedCount])
	}
}

// The PyPI root version is always a placeholder — nothing in this adapter
// executes setup.py/pyproject.toml to get a real one. That must be
// disclosed so a reader can tell "genuinely 0.0.0" apart from "could not
// determine" instead of guessing.
func TestRootVersionPlaceholderDisclosed(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/mixed")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root == nil || root.Attr["pypi.version_source"] != "unresolved-placeholder" {
		t.Errorf("root version placeholder not disclosed: %+v", root)
	}
}

func TestPyPIResolveIsDeterministic(t *testing.T) {
	a := &Adapter{}
	var first []string
	for i := 0; i < 10; i++ {
		g, err := a.Resolve("testdata/realworld")
		if err != nil {
			t.Fatal(err)
		}
		var seq []string
		for _, e := range g.SortedEdges() {
			seq = append(seq, e.From+"->"+e.To)
		}
		if i == 0 {
			first = seq
			continue
		}
		for j := range seq {
			if seq[j] != first[j] {
				t.Fatalf("run %d differs at edge %d", i, j)
			}
		}
	}
}

// TestCompoundSpecifiersAreDisclosedWithCleanNames covers the requirements.txt
// side of the reported parser finding (HoneyBadger Vanguard, iHBV-TM-022).
//
// The fixture holds one ordinary pin, one comma-joined range, one compound
// whose first clause is "==" , and one bare URL. Pre-fix the parser reported
// the range as "urllib3<3," in depsnort.unresolved_names, minted a node with
// the malformed PURL "pkg:pypi/foo@1.0,!=1.0.1" for the "==" compound, and
// silently dropped nothing only because it mangled the URL into a name.
func TestCompoundSpecifiersAreDisclosedWithCleanNames(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/compound")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root == nil {
		t.Fatal("root missing")
	}

	// Only the single genuine pin becomes a node.
	if g.Len() != 2 {
		var ids []string
		for _, n := range g.SortedNodes() {
			ids = append(ids, n.ID)
		}
		t.Fatalf("nodes = %d, want 2 (root + flask); got %v", g.Len(), ids)
	}
	if g.Get(purl.NewPyPI("flask", "2.0.1").String()) == nil {
		t.Error("flask==2.0.1 was not resolved")
	}

	// A compound specifier is a RANGE (D-01) — never a pin, even when one of
	// its clauses is "==" — so no node may be minted from it.
	for _, n := range g.SortedNodes() {
		if strings.ContainsAny(n.Version, ",<>=!") {
			t.Errorf("node %q carries a malformed version %q", n.ID, n.Version)
		}
		if strings.ContainsAny(n.Name, ",<>=!") {
			t.Errorf("node %q carries a corrupted name %q", n.ID, n.Name)
		}
	}

	unresolved := root.Attr[graph.AttrUnresolved]
	for _, want := range []string{"urllib3", "foo"} {
		var found bool
		for _, got := range strings.Split(unresolved, ",") {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s = %q, want it to disclose %q as a clean bare name", graph.AttrUnresolved, unresolved, want)
		}
	}
	if strings.Contains(unresolved, "urllib3<3") {
		t.Errorf("%s = %q, still carries the corrupted name", graph.AttrUnresolved, unresolved)
	}
	// The bare URL is not a requirement at all; it must be DISCLOSED as
	// unparseable rather than silently dropped (D-24).
	if !strings.Contains(unresolved, "<unparseable:") {
		t.Errorf("%s = %q, want an <unparseable:...> token for the bare URL line", graph.AttrUnresolved, unresolved)
	}
	if root.Attr[graph.AttrUnresolvedCount] != "3" {
		t.Errorf("%s = %q, want \"3\" (urllib3, foo, and the unparseable URL)",
			graph.AttrUnresolvedCount, root.Attr[graph.AttrUnresolvedCount])
	}
}

// TestUTF8BOMDoesNotDropFirstDependency guards the regression the anchored
// parser would otherwise have introduced: strings.TrimSpace does not strip
// U+FEFF, so a requirements.txt written by `pip freeze` under Windows
// PowerShell 5.1 would have failed the anchored name match on line 1 and lost
// that dependency with no disclosure at all.
func TestUTF8BOMDoesNotDropFirstDependency(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/bom")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if n := g.Get(purl.NewPyPI("requests", "2.31.0").String()); n == nil {
		t.Error("the BOM-prefixed first dependency was dropped")
	}
	if n := g.Get(purl.NewPyPI("click", "8.0.1").String()); n == nil {
		t.Error("click==8.0.1 was not resolved")
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root != nil && root.Attr[graph.AttrUnresolvedCount] != "" {
		t.Errorf("a BOM must not register as a coverage gap, got %s = %q",
			graph.AttrUnresolvedCount, root.Attr[graph.AttrUnresolvedCount])
	}
}
