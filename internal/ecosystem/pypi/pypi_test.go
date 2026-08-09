package pypi

import (
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
	// Extras stripped, name normalized, marker ignored.
	if n := g.Get(purl.NewPyPI("flask-sqlalchemy", "2.5.1").String()); n == nil {
		t.Error("Flask_SQLAlchemy[async]==2.5.1 with a marker was not resolved")
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
