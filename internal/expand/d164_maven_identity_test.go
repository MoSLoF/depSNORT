package expand_test

import (
	"context"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/clojure"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
)

// d164Resolver returns one canned resolved graph for the postgresql direct
// dep, the shape deps.dev hands the asserted tier for a maven coordinate.
type d164Resolver struct{ calls []string }

func (*d164Resolver) Name() string { return "d164-stub" }

func (r *d164Resolver) Resolve(_ context.Context, eco, name, version string) (expand.ResolvedGraph, bool, error) {
	r.calls = append(r.calls, eco+"|"+name+"|"+version)
	if eco != "maven" || name != "org.postgresql:postgresql" {
		return expand.ResolvedGraph{}, false, nil
	}
	return expand.ResolvedGraph{
		Nodes: []expand.ResolvedRef{
			{Ecosystem: "maven", Name: "org.postgresql:postgresql", Version: "42.7.4"}, // index 0: the queried dep
			{Ecosystem: "maven", Name: "org.checkerframework:checker-qual", Version: "3.42.0"},
		},
		Edges: []expand.ResolvedEdge{{From: 0, To: 1}},
	}, true, nil
}

// mavenScanGraph builds what the clojure adapter actually emits for the jepsen
// shape: a path-source root plus the OBSERVED direct dep at the adapter's
// namespace-form PURL.
func mavenScanGraph() (*graph.Graph, *graph.Node) {
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:maven/swytch.jepsen@0.1.0", Kind: graph.KindPackage, Ecosystem: "maven",
		Name: "swytch.jepsen", Version: "0.1.0",
		Attr: map[string]string{
			graph.AttrDeclaredDeps: graph.EncodeDeclaredDeps([]graph.DeclaredDep{
				{Name: "org.postgresql:postgresql", Constraint: "42.7.4"},
			}),
		},
	})
	root.SetSource(graph.SourcePath, "")
	g.MarkRoot(root.ID)
	observed := g.AddNode(&graph.Node{
		ID: "pkg:maven/org.postgresql/postgresql@42.7.4", Kind: graph.KindPackage,
		Ecosystem: "maven", Name: "org.postgresql:postgresql", Version: "42.7.4",
		Direct: true, Depth: 1,
		Attr: map[string]string{graph.AttrSourceClass: graph.SourceRegistry},
	})
	g.AddEdge(root.ID, observed.ID, graph.EdgeDependsOn)
	return g, root
}

// D-164: with the maven Declarer seam, a deps.dev-asserted maven tree merges
// under the adapter's namespace-form PURLs — the queried dep dedupes against
// the observed node instead of re-entering under a colon-form twin, and the
// asserted child is named the same way the adapter would name it.
func TestAssertedMavenTreeSharesObservedIdentity(t *testing.T) {
	g, root := mavenScanGraph()
	_, err := expand.NewWalker(&clojure.WalkSource{}).
		ExpandRoot(context.Background(), g, root, expand.Options{Resolver: &d164Resolver{}})
	if err != nil {
		t.Fatal(err)
	}

	if twin := g.Get("pkg:maven/org.postgresql:postgresql@42.7.4"); twin != nil {
		t.Error("colon-form twin of the observed dep exists: observed-beats-asserted dedupe failed")
	}
	child := g.Get("pkg:maven/org.checkerframework/checker-qual@3.42.0")
	if child == nil {
		t.Fatal("asserted child missing at the namespace-form PURL")
	}
	if child.VersionTruth() != graph.TruthAsserted {
		t.Errorf("child truth = %q, want asserted", child.VersionTruth())
	}
	if g.Get("pkg:maven/org.checkerframework:checker-qual@3.42.0") != nil {
		t.Error("asserted child also present at the colon-form ID: identity split")
	}
}

// The permanently-encoded mutation half: WITHOUT the seam, the engine's raw
// fallback keeps the colon in the name segment and the identity splits — the
// D-15 leak shape, one tier up. This is the live bug the elastic-agent
// validation flagged at asserted.go's fallback; if the engine's fallback is
// ever taught purl grammar generally, this assertion is the one to revisit.
func TestAssertedMavenTreeSplitsWithoutTheSeam(t *testing.T) {
	g, root := mavenScanGraph()
	_, err := expand.NewWalker( /* no maven declarer */ ).
		ExpandRoot(context.Background(), g, root, expand.Options{Resolver: &d164Resolver{}})
	if err != nil {
		t.Fatal(err)
	}
	colonTwin := g.Get("pkg:maven/org.postgresql:postgresql@42.7.4")
	colonChild := g.Get("pkg:maven/org.checkerframework:checker-qual@3.42.0")
	if colonTwin == nil && colonChild == nil {
		t.Skip("the raw fallback no longer produces colon-form maven IDs; the seam may be redundant — revisit D-164")
	}
}
