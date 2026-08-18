package expand_test

import (
	"context"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
)

// fakePyPI is a Declarer over a fixed metadata table. Absent key = never read.
type fakePyPI struct {
	table map[string][]expand.Declaration
	calls int
}

func (*fakePyPI) Ecosystem() string { return "pypi" }

// Identify folds per PEP 503, which is the leak D-15 found: without this,
// Flask_SQLAlchemy and flask-sqlalchemy become two nodes.
func (*fakePyPI) Identify(name string) (string, string) {
	canon := strings.ToLower(name)
	canon = strings.NewReplacer("_", "-", ".", "-").Replace(canon)
	for strings.Contains(canon, "--") {
		canon = strings.ReplaceAll(canon, "--", "-")
	}
	if canon == "" {
		return "", ""
	}
	return "pkg:pypi/" + canon, canon
}

func (f *fakePyPI) Declared(_ context.Context, coords []datasource.Coord) (map[string][]expand.Declaration, error) {
	f.calls++
	out := map[string][]expand.Declaration{}
	for _, c := range coords {
		if d, ok := f.table[c.Key()]; ok {
			out[c.Key()] = d
		}
	}
	return out, nil
}

func rootWith(t *testing.T, pins map[string]string) (*graph.Graph, *graph.Node) {
	t.Helper()
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/app", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "app"})
	g.MarkRoot(root.ID)
	for name, ver := range pins {
		n := g.AddNode(&graph.Node{
			ID: "pkg:pypi/" + name + "@" + ver, Kind: graph.KindPackage,
			Ecosystem: "pypi", Name: name, Version: ver, Direct: true, Depth: 1,
		})
		g.AddEdge(root.ID, n.ID, graph.EdgeDependsOn)
	}
	return g, root
}

// The motivating case. requirements.txt pins one package; the layer it drags in
// is nowhere in the file. Today that layer is fetched and discarded.
func TestDiscoversTheLayerBelowASinglePin(t *testing.T) {
	g, root := rootWith(t, map[string]string{"totallyinnocent": "0.11.2"})
	d := &fakePyPI{table: map[string][]expand.Declaration{
		"pypi|totallyinnocent|0.11.2": {
			{Name: "requests", Constraint: ">=2.0"},
			{Name: "Flask_SQLAlchemy", Constraint: "~=3.0"},
			{Name: "pytest", Constraint: ">=7", Optional: true},
		},
	}}

	res, err := expand.NewWalker(d).ExpandRoot(context.Background(), g, root, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("%-34s ver=%-8q depth=%d unversioned=%s frontier=%s constraint=%q",
			n.ID, n.Version, n.Depth, n.Attr[expand.AttrUnversioned],
			n.Attr[expand.AttrFrontier], n.Attr[expand.AttrDeclaredConstraint])
	}
	t.Logf("%+v", res)

	if res.Discovered != 2 {
		t.Errorf("discovered = %d, want 2 (optional pytest excluded by default)", res.Discovered)
	}
	// PEP 503: the node is flask-sqlalchemy, not Flask_SQLAlchemy.
	if g.Get("pkg:pypi/flask-sqlalchemy") == nil {
		t.Error("declared name was not folded per PEP 503")
	}
	req := g.Get("pkg:pypi/requests")
	if req == nil {
		t.Fatal("requests not discovered")
	}
	if req.Version != "" {
		t.Errorf("version = %q, want empty — a guessed version is indistinguishable from a real one", req.Version)
	}
	if req.Attr[expand.AttrDeclaredConstraint] != ">=2.0" {
		t.Errorf("constraint = %q, want the raw declaration", req.Attr[expand.AttrDeclaredConstraint])
	}
	// The honest limit: discovered nodes are the frontier. Nothing below is seen.
	if req.Attr[expand.AttrFrontier] != "true" || res.Frontier != 2 {
		t.Errorf("frontier not marked: attr=%q count=%d", req.Attr[expand.AttrFrontier], res.Frontier)
	}
}

// Per-root: a declaration must never be satisfied by another root's pinned
// package. Borrowing root B's version to answer root A's declaration produces
// an edge indistinguishable from a real one.
func TestDeclarationNeverBorrowsAnotherRootsPin(t *testing.T) {
	g, rootA := rootWith(t, map[string]string{"totallyinnocent": "0.11.2"})
	rootB := g.AddNode(&graph.Node{ID: "pkg:pypi/other", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "other"})
	g.MarkRoot(rootB.ID)
	// Root B has requests PINNED. Root A only declares it.
	pinned := g.AddNode(&graph.Node{
		ID: "pkg:pypi/requests@2.31.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "requests", Version: "2.31.0", Depth: 1,
	})
	g.AddEdge(rootB.ID, pinned.ID, graph.EdgeDependsOn)

	d := &fakePyPI{table: map[string][]expand.Declaration{
		"pypi|totallyinnocent|0.11.2": {{Name: "requests", Constraint: ">=2.0"}},
	}}
	if _, err := expand.NewWalker(d).ExpandRoot(context.Background(), g, rootA, expand.Options{}); err != nil {
		t.Fatal(err)
	}

	for _, e := range g.SortedEdges() {
		if e.To == pinned.ID && strings.Contains(e.From, "totallyinnocent") {
			t.Fatal("root A's declaration was satisfied by root B's pinned version")
		}
	}
	if g.Get("pkg:pypi/requests") == nil {
		t.Error("want a separate unversioned node under root A")
	}
}

// A coordinate absent from the metadata response was NOT READ. Treating that as
// "declares nothing" turns an unfetched package into a confident leaf — the
// D-42 pattern: reporting success because the call ran, not because it answered.
func TestUnreadCoordinateIsNotAConfidentLeaf(t *testing.T) {
	g, root := rootWith(t, map[string]string{"totallyinnocent": "0.11.2", "quiet": "1.0.0"})
	d := &fakePyPI{table: map[string][]expand.Declaration{
		"pypi|quiet|1.0.0": {}, // present and empty: genuinely declares nothing
	}}

	res, err := expand.NewWalker(d).ExpandRoot(context.Background(), g, root, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Unread != 1 {
		t.Errorf("unread = %d, want 1", res.Unread)
	}
	if g.Get("pkg:pypi/totallyinnocent@0.11.2").Attr[expand.AttrFrontier] != "true" {
		t.Error("unread package must be a frontier, not a leaf")
	}
	if g.Get("pkg:pypi/quiet@1.0.0").Attr[expand.AttrFrontier] == "true" {
		t.Error("a package that genuinely declares nothing is a leaf, not a frontier")
	}
}
