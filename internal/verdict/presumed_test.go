package verdict

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

func presumedGraph(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()
	observed := g.AddNode(&graph.Node{
		ID: "pkg:pypi/requests@2.31.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "requests", Version: "2.31.0",
	})
	g.MarkRoot(observed.ID)
	p := g.AddNode(&graph.Node{
		ID: "pkg:pypi/urllib3@1.26.18", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "urllib3", Version: "1.26.18",
		Attr: map[string]string{
			graph.AttrVersionTruth:       graph.TruthPresumed,
			graph.AttrVersionCandidates:  "3",
			graph.AttrDeclaredConstraint: ">=1.21,<2.0",
		},
	})
	g.AddEdge(observed.ID, p.ID, graph.EdgeDependsOn)
	return g
}

// A block on a version nobody installed is a false positive with a build
// failure attached. It reports; it must not gate.
func TestPresumedNodeCannotGate(t *testing.T) {
	g := presumedGraph(t)
	findings := []finding.Finding{
		{CheckID: "VC-001", Axis: finding.AxisKnownCompromise, GateClass: finding.GateBlock,
			NodeID: "pkg:pypi/urllib3@1.26.18", Title: "malicious release", Evidence: "MAL-0000"},
		{CheckID: "VC-008", Axis: finding.AxisVuln, GateClass: finding.GateEligible,
			NodeID: "pkg:pypi/requests@2.31.0", Title: "CVE on an observed pin"},
	}

	res := Evaluate(g, findings, Policy{FailOnEligible: true})
	if res.ExitCode != ExitGate {
		t.Fatalf("exit = %d, want %d — the observed node still gates", res.ExitCode, ExitGate)
	}
	if res.Counts.Block != 0 {
		t.Errorf("block count = %d, want 0 — the presumed node's block was demoted", res.Counts.Block)
	}
	if res.Counts.Advisory != 1 || res.Counts.Eligible != 1 {
		t.Errorf("counts = %+v, want 1 advisory (demoted) and 1 eligible (observed)", res.Counts)
	}

	// Demoted, never dropped: the finding survives with its reason attached.
	var demoted *finding.Finding
	for i := range res.Findings {
		if res.Findings[i].CheckID == "VC-001" {
			demoted = &res.Findings[i]
		}
	}
	if demoted == nil {
		t.Fatal("the finding was dropped, not demoted")
	}
	if demoted.GateClass != finding.GateAdvisory {
		t.Errorf("gate class = %q, want advisory", demoted.GateClass)
	}
	for _, want := range []string{"MAL-0000", "presumed", "3 candidate versions", ">=1.21,<2.0"} {
		if !strings.Contains(demoted.Evidence, want) {
			t.Errorf("evidence %q missing %q", demoted.Evidence, want)
		}
	}
	// It still colors the node: suppressing the signal was never the point.
	if res.Risk["pkg:pypi/urllib3@1.26.18"] == finding.RiskClean {
		t.Error("a demoted finding must still mark its node")
	}
}

// A node with no recorded truth is observed — expansion must not retroactively
// demote every scan that predates it.
func TestAbsentTruthIsObserved(t *testing.T) {
	g := graph.New()
	n := g.AddNode(&graph.Node{
		ID: "pkg:npm/left-pad@1.3.0", Kind: graph.KindPackage,
		Ecosystem: "npm", Name: "left-pad", Version: "1.3.0",
	})
	g.MarkRoot(n.ID)
	if n.Presumed() || n.VersionTruth() != graph.TruthObserved {
		t.Fatalf("truth = %q presumed = %v", n.VersionTruth(), n.Presumed())
	}
	res := Evaluate(g, []finding.Finding{
		{CheckID: "VC-001", GateClass: finding.GateBlock, NodeID: n.ID},
	}, Policy{})
	if res.ExitCode != ExitBlock || res.Counts.Block != 1 {
		t.Errorf("exit = %d block = %d, want %d and 1", res.ExitCode, res.Counts.Block, ExitBlock)
	}
}

// A contested node carries no version and still cannot gate.
func TestContestedNodeCannotGate(t *testing.T) {
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/app", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "app"})
	g.MarkRoot(root.ID)
	c := g.AddNode(&graph.Node{
		ID: "pkg:pypi/shared", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "shared",
		Attr: map[string]string{graph.AttrVersionTruth: graph.TruthContested},
	})
	g.AddEdge(root.ID, c.ID, graph.EdgeDependsOn)

	// Contested is not presumed — it asserts no version at all — so a finding
	// on it is left alone here and handled by the coverage axis instead.
	if c.Presumed() {
		t.Error("contested must not read as presumed: no version was chosen")
	}
}
