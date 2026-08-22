package verdict

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// twoRootGraph builds: realapp -> shared -> deep, fixture -> shared,
// fixture -> evil, plus an install hook declared by evil. "shared" is reachable
// from BOTH roots; "evil" and its hook only from the fixture root.
func twoRootGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/realapp@1", Kind: graph.KindPackage, Name: "realapp", Version: "1"})
	g.AddNode(&graph.Node{ID: "pkg:npm/fixture-root@1", Kind: graph.KindPackage, Name: "fixture-root", Version: "1"})
	g.AddNode(&graph.Node{ID: "pkg:npm/shared@1", Kind: graph.KindPackage, Name: "shared", Version: "1"})
	g.AddNode(&graph.Node{ID: "pkg:npm/deep@1", Kind: graph.KindPackage, Name: "deep", Version: "1"})
	g.AddNode(&graph.Node{ID: "pkg:npm/evil@1", Kind: graph.KindPackage, Name: "evil", Version: "1"})
	g.AddNode(&graph.Node{ID: "hook:evil-postinstall", Kind: graph.KindInstallHook, Name: "postinstall"})
	g.MarkRoot("pkg:npm/realapp@1")
	g.MarkRoot("pkg:npm/fixture-root@1")
	g.AddEdge("pkg:npm/realapp@1", "pkg:npm/shared@1", graph.EdgeDependsOn)
	g.AddEdge("pkg:npm/shared@1", "pkg:npm/deep@1", graph.EdgeDependsOn)
	g.AddEdge("pkg:npm/fixture-root@1", "pkg:npm/shared@1", graph.EdgeDependsOn)
	g.AddEdge("pkg:npm/fixture-root@1", "pkg:npm/evil@1", graph.EdgeDependsOn)
	g.AddEdge("pkg:npm/evil@1", "hook:evil-postinstall", graph.EdgeDeclaresHook)
	return g
}

// Every finding must carry its COMPLETE root attribution — all roots that reach
// the node, over any edge type (a hook is attributed through its declares-hook
// edge, which no depends-on path covers).
func TestFindingsCarryCompleteRootAttribution(t *testing.T) {
	g := twoRootGraph()
	res := Evaluate(g, []finding.Finding{
		{CheckID: "VC-008", NodeID: "pkg:npm/shared@1", GateClass: finding.GateAdvisory, Confidence: 1, Title: "shared vuln"},
		{CheckID: "VC-002b", NodeID: "hook:evil-postinstall", GateClass: finding.GateEligible, Confidence: 1, Title: "hook net"},
	}, Policy{})

	byNode := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byNode[f.NodeID] = f
	}
	shared := byNode["pkg:npm/shared@1"].ReachableRoots
	if len(shared) != 2 || shared[0] != "pkg:npm/fixture-root@1" || shared[1] != "pkg:npm/realapp@1" {
		t.Errorf("shared node must list BOTH roots, sorted; got %v", shared)
	}
	hook := byNode["hook:evil-postinstall"].ReachableRoots
	if len(hook) != 1 || hook[0] != "pkg:npm/fixture-root@1" {
		t.Errorf("hook must be attributed through the declares-hook edge; got %v", hook)
	}
	// Without -real-roots, attribution is stamped but nothing is adjudicated.
	for _, f := range res.Findings {
		if f.Contained {
			t.Errorf("no RealRoots designated: nothing may be labeled contained (%s)", f.NodeID)
		}
	}
}

// With real roots designated, a finding no designated root reaches is labeled
// contained WITH the proof in its evidence; one a real root reaches is not.
func TestContainmentAdjudicatesOnlyUnreachableFindings(t *testing.T) {
	g := twoRootGraph()
	res := Evaluate(g, []finding.Finding{
		{CheckID: "VC-001", NodeID: "pkg:npm/evil@1", GateClass: finding.GateBlock, Confidence: 1, Title: "malicious", Evidence: "on the list"},
		{CheckID: "VC-008", NodeID: "pkg:npm/shared@1", GateClass: finding.GateAdvisory, Confidence: 1, Title: "shared vuln"},
	}, Policy{RealRoots: []string{"realapp"}})

	byNode := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byNode[f.NodeID] = f
	}
	evil := byNode["pkg:npm/evil@1"]
	if !evil.Contained {
		t.Error("evil is reachable only from the fixture root and must be labeled contained")
	}
	if !strings.Contains(evil.Evidence, "contained: no designated real root reaches this node") ||
		!strings.Contains(evil.Evidence, "pkg:npm/fixture-root@1") {
		t.Errorf("containment label must carry the reachability proof, got %q", evil.Evidence)
	}
	if shared := byNode["pkg:npm/shared@1"]; shared.Contained {
		t.Error("shared is reachable from the designated real root and must NOT be labeled contained")
	}
}

// THE ANTI-BLINDNESS INVARIANT: containment is a label, never a suppression.
// A contained block-class finding keeps its gate class, its counts, and the
// exit code it would have produced without the label.
func TestContainmentNeverChangesGateOrExitCode(t *testing.T) {
	g := twoRootGraph()
	fs := []finding.Finding{
		{CheckID: "VC-001", NodeID: "pkg:npm/evil@1", GateClass: finding.GateBlock, Confidence: 1, Title: "malicious"},
	}
	plain := Evaluate(twoRootGraph(), append([]finding.Finding(nil), fs...), Policy{})
	adjud := Evaluate(g, fs, Policy{RealRoots: []string{"realapp"}})

	if adjud.ExitCode != plain.ExitCode {
		t.Fatalf("containment changed the exit code: %d -> %d", plain.ExitCode, adjud.ExitCode)
	}
	if adjud.ExitCode != ExitBlock {
		t.Fatalf("a contained block finding must still block, got exit %d", adjud.ExitCode)
	}
	if adjud.Counts != plain.Counts {
		t.Errorf("containment changed the counts: %+v -> %+v", plain.Counts, adjud.Counts)
	}
	if !adjud.Findings[0].Contained || adjud.Findings[0].GateClass != finding.GateBlock {
		t.Errorf("finding must be labeled contained AND keep its gate class, got %+v", adjud.Findings[0])
	}
}
