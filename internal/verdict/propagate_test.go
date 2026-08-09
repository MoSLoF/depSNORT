package verdict

import (
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// buildHookChain models the ChainDrop shape: pkg -> hook -> {artifact, sink}.
func buildHookChain() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/evil@1.0.0", Kind: graph.KindPackage, Name: "evil", Version: "1.0.0"})
	g.AddNode(&graph.Node{ID: "hook:evil#preinstall", Kind: graph.KindInstallHook, Name: "preinstall"})
	g.AddNode(&graph.Node{ID: "artifact:evil#setup.mjs", Kind: graph.KindReferencedArtifact, Name: "setup.mjs"})
	g.AddNode(&graph.Node{ID: "sink:evil#NPM_TOKEN", Kind: graph.KindSink, Name: "NPM_TOKEN"})
	g.AddNode(&graph.Node{ID: "pkg:npm/quiet@1.0.0", Kind: graph.KindPackage, Name: "quiet", Version: "1.0.0"})

	g.AddEdge("pkg:npm/evil@1.0.0", "hook:evil#preinstall", graph.EdgeDeclaresHook)
	g.AddEdge("hook:evil#preinstall", "artifact:evil#setup.mjs", graph.EdgeHookExecs)
	g.AddEdge("hook:evil#preinstall", "sink:evil#NPM_TOKEN", graph.EdgeHookReadsEnv)
	return g
}

func TestRiskPropagatesThroughInstallSubgraph(t *testing.T) {
	g := buildHookChain()
	res := Evaluate(g, []finding.Finding{{
		CheckID: "VC-002d", NodeID: "pkg:npm/evil@1.0.0",
		GateClass: finding.GateBlock, Severity: finding.SevCritical, Confidence: 1,
	}}, Policy{})

	if res.ExitCode != ExitBlock {
		t.Fatalf("exit = %d, want %d", res.ExitCode, ExitBlock)
	}
	for _, id := range []string{
		"hook:evil#preinstall",
		"artifact:evil#setup.mjs",
		"sink:evil#NPM_TOKEN",
	} {
		if got := res.Risk[id]; got != finding.RiskFlagged {
			t.Errorf("%s risk = %q, want flagged (chain must render hot)", id, got)
		}
		if n := g.Get(id); n != nil && n.Risk != finding.RiskFlagged {
			t.Errorf("%s node risk = %q, want flagged", id, n.Risk)
		}
	}
	// An unrelated package must stay clean — propagation is scoped, not global.
	if res.Risk["pkg:npm/quiet@1.0.0"] != finding.RiskClean {
		t.Errorf("unrelated package became %q", res.Risk["pkg:npm/quiet@1.0.0"])
	}
}

func TestPropagationNeverDowngrades(t *testing.T) {
	g := buildHookChain()
	// The package is only WARNED, but the artifact has its own FLAG.
	res := Evaluate(g, []finding.Finding{
		{CheckID: "VC-002a", NodeID: "pkg:npm/evil@1.0.0", GateClass: finding.GateEligible, Confidence: 1},
		{CheckID: "VC-001", NodeID: "artifact:evil#setup.mjs", GateClass: finding.GateBlock, Confidence: 1},
	}, Policy{})

	if got := res.Risk["artifact:evil#setup.mjs"]; got != finding.RiskFlagged {
		t.Errorf("artifact risk = %q, want flagged (must not be softened to warned)", got)
	}
	if got := res.Risk["sink:evil#NPM_TOKEN"]; got != finding.RiskWarned {
		t.Errorf("sink risk = %q, want warned (inherited from package)", got)
	}
}

func TestNoInstallEdgesIsNoop(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/a@1", Kind: graph.KindPackage, Name: "a"})
	g.AddNode(&graph.Node{ID: "pkg:npm/b@1", Kind: graph.KindPackage, Name: "b"})
	g.AddEdge("pkg:npm/a@1", "pkg:npm/b@1", graph.EdgeDependsOn)

	res := Evaluate(g, []finding.Finding{{
		CheckID: "X", NodeID: "pkg:npm/a@1", GateClass: finding.GateBlock, Confidence: 1,
	}}, Policy{})
	// depends-on is NOT an install-time edge: risk must not leak down the
	// declared tree, or every transitive dep of a bad package turns red.
	if res.Risk["pkg:npm/b@1"] != finding.RiskClean {
		t.Errorf("risk leaked across depends-on: b = %q", res.Risk["pkg:npm/b@1"])
	}
}
