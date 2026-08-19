package depsdev

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
)

type fakeDoer struct {
	body   string
	status int
	calls  int
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	st := f.status
	if st == 0 {
		st = 200
	}
	return &http.Response{StatusCode: st, Body: io.NopCloser(strings.NewReader(f.body)), Header: make(http.Header)}, nil
}

func client(t *testing.T, f *fakeDoer) *Client {
	t.Helper()
	c := New(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = f
	return c
}

// A real deps.dev :dependencies response shape: node 0 is SELF, the rest are
// resolved concrete versions, edges wire them.
const sampleResponse = `{
  "nodes": [
    {"versionKey": {"system": "PYPI", "name": "flask", "version": "3.0.0"}, "relation": "SELF"},
    {"versionKey": {"system": "PYPI", "name": "werkzeug", "version": "3.0.1"}, "relation": "DIRECT"},
    {"versionKey": {"system": "PYPI", "name": "markupsafe", "version": "2.1.3"}, "relation": "INDIRECT"}
  ],
  "edges": [
    {"fromNode": 0, "toNode": 1},
    {"fromNode": 1, "toNode": 2}
  ]
}`

func TestResolveReturnsConcreteGraph(t *testing.T) {
	c := client(t, &fakeDoer{body: sampleResponse})
	rg, ok, err := c.Resolve(context.Background(), "pypi", "flask", "3.0.0")
	if err != nil || !ok {
		t.Fatalf("Resolve ok=%v err=%v", ok, err)
	}
	if len(rg.Nodes) != 3 || len(rg.Edges) != 2 {
		t.Fatalf("nodes=%d edges=%d, want 3/2", len(rg.Nodes), len(rg.Edges))
	}
	if rg.Nodes[1].Ecosystem != "pypi" || rg.Nodes[1].Name != "werkzeug" || rg.Nodes[1].Version != "3.0.1" {
		t.Errorf("node[1] = %+v", rg.Nodes[1])
	}
}

func TestUnsupportedEcosystemReportsNoAnswer(t *testing.T) {
	f := &fakeDoer{body: sampleResponse}
	c := client(t, f)
	_, ok, err := c.Resolve(context.Background(), "composer", "monolog/monolog", "3.0.0")
	if ok || err != nil {
		t.Errorf("composer: ok=%v err=%v, want (false, nil)", ok, err)
	}
	if f.calls != 0 {
		t.Error("an unsupported ecosystem must not hit the network")
	}
}

func Test404IsNoAnswerNotError(t *testing.T) {
	c := client(t, &fakeDoer{status: 404, body: `{}`})
	_, ok, err := c.Resolve(context.Background(), "pypi", "ghost", "9.9.9")
	if ok || err != nil {
		t.Errorf("404: ok=%v err=%v, want (false, nil)", ok, err)
	}
}

// End to end through the walk: AssertRoot merges the resolved graph, marking the
// dependencies asserted and leaving the observed root untouched.
func TestAssertRootMergesAssertedSubtree(t *testing.T) {
	c := client(t, &fakeDoer{body: sampleResponse})
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/flask@3.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "flask", Version: "3.0.0"})
	root.SetSource(graph.SourceRegistry, "")
	g.MarkRoot(root.ID)

	w := expand.NewWalker(&pypi.WalkSource{})
	res, err := w.AssertRoot(context.Background(), g, root, c)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resolved || res.Asserted != 2 {
		t.Fatalf("result = %+v, want resolved with 2 asserted", res)
	}
	wz := g.Get("pkg:pypi/werkzeug@3.0.1")
	if wz == nil || wz.VersionTruth() != graph.TruthAsserted {
		t.Errorf("werkzeug not asserted: %+v", wz)
	}
	if wz.Attr[expand.AttrAssertedBy] != "deps.dev" {
		t.Errorf("asserted_by = %q, want deps.dev", wz.Attr[expand.AttrAssertedBy])
	}
	// The root stays observed — a fact must not be demoted to a claim.
	if root.VersionTruth() != graph.TruthObserved {
		t.Errorf("root truth = %q, want observed", root.VersionTruth())
	}
	// Edges landed.
	var edge bool
	for _, e := range g.SortedEdges() {
		if e.From == "pkg:pypi/werkzeug@3.0.1" && e.To == "pkg:pypi/markupsafe@2.1.3" {
			edge = true
		}
	}
	if !edge {
		t.Error("indirect edge werkzeug->markupsafe not merged")
	}
}
