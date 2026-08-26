package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
)

// D-143: expandTransitive folded only res.Unread, so a walk stopped by the
// DEPTH BOUND contributed nothing to coverage — while its own doc comment
// claimed it folded "every root's frontier and unread counts", and the
// -expand-depth help told operators that 0 meant "full depth" when 0 selects
// the engine's default bound. A default scan of a deep tree therefore reported
// a complete all-clear over everything past layer eight.
//
// D-24 exempted this bound from degrading coverage on the stated grounds that
// it is "a limit the operator chose". That reasoning is kept exactly where it
// holds — an explicit -expand-depth is still a deliberately partial walk — and
// dropped where it does not, which is every scan that never passed the flag.

type d143Declarer struct{ links int }

func (*d143Declarer) Ecosystem() string { return "pypi" }

func (*d143Declarer) Identify(name, version string) (string, string) {
	if name == "" {
		return "", ""
	}
	id := "pkg:pypi/" + name
	if version != "" {
		id += "@" + version
	}
	return id, name
}

func (d *d143Declarer) Declared(_ context.Context, coords []datasource.Coord) (map[string][]expand.Declaration, error) {
	out := map[string][]expand.Declaration{}
	for _, c := range coords {
		var n int
		if _, err := fmt.Sscanf(c.Name, "c%d", &n); err != nil {
			continue
		}
		if n >= d.links {
			out[c.Key()] = []expand.Declaration{}
			continue
		}
		out[c.Key()] = []expand.Declaration{{Name: fmt.Sprintf("c%d", n+1)}}
	}
	return out, nil
}

func (*d143Declarer) Versions(context.Context, string, string) ([]string, error) {
	return []string{"1.0.0"}, nil
}
func (*d143Declarer) CompareVersions(a, b string) int { return strings.Compare(a, b) }
func (*d143Declarer) Satisfies(constraint, _ string) (bool, bool) {
	return constraint == "", true
}

func d143Graph(t *testing.T) (*graph.Graph, []*graph.Node) {
	t.Helper()
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/app", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "app"})
	g.MarkRoot(root.ID)
	n := g.AddNode(&graph.Node{
		ID: "pkg:pypi/c0@1.0.0", Kind: graph.KindPackage, Ecosystem: "pypi",
		Name: "c0", Version: "1.0.0", Direct: true, Depth: 1,
	})
	g.AddEdge(root.ID, n.ID, graph.EdgeDependsOn)
	return g, []*graph.Node{root}
}

// TestD143DefaultBoundDegradesCoverage: the operator passed nothing, so the
// bound is ours, and a scan that stopped at it is not an all-clear.
func TestD143DefaultBoundDegradesCoverage(t *testing.T) {
	g, roots := d143Graph(t)
	cov := expandTransitive(g, roots, []expand.Declarer{&d143Declarer{links: 40}}, nil, 0)
	if cov.Stats.Gaps == 0 {
		t.Fatalf("a default-bounded walk over a 40-deep chain must degrade coverage; got %+v", cov)
	}
	if !strings.Contains(cov.Note, "depth bound") {
		t.Errorf("the report should say the bound stopped the walk, got note %q", cov.Note)
	}
}

// TestD143OperatorChosenBoundDoesNotDegrade preserves D-24's exemption where its
// premise actually holds: -expand-depth=2 is someone stepping the tree on
// purpose, and failing their build for it is the warning tax that gets a tool
// muted.
func TestD143OperatorChosenBoundDoesNotDegrade(t *testing.T) {
	g, roots := d143Graph(t)
	cov := expandTransitive(g, roots, []expand.Declarer{&d143Declarer{links: 40}}, nil, 2)
	if cov.Stats.Gaps != 0 {
		t.Errorf("an explicitly chosen depth is a deliberate partial walk, not a gap; got %+v", cov)
	}
}

// TestD143ShallowTreeDegradesNothing is the false-positive boundary at the CLI
// seam: the bound is set on every walk, so a chain that ends before it must
// leave coverage untouched.
func TestD143ShallowTreeDegradesNothing(t *testing.T) {
	g, roots := d143Graph(t)
	cov := expandTransitive(g, roots, []expand.Declarer{&d143Declarer{links: 2}}, nil, 0)
	if cov.Stats.Gaps != 0 {
		t.Errorf("the walk ran out of tree, not out of depth; got %+v", cov)
	}
	if strings.Contains(cov.Note, "depth bound") {
		t.Errorf("no bound was hit; note should not mention it: %q", cov.Note)
	}
}

// TestD143NotesCompose: a deep tree walked with no asserted tier trips BOTH
// notes, and the second must not erase the first.
func TestD143NotesCompose(t *testing.T) {
	g, roots := d143Graph(t)
	cov := expandTransitive(g, roots, []expand.Declarer{&d143Declarer{links: 40}}, nil, 0)
	if !strings.Contains(cov.Note, "depth bound") || !strings.Contains(cov.Note, "PRESUMED") {
		t.Errorf("both caveats apply and both must survive; got %q", cov.Note)
	}
}
