package verdict

import (
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

func twoNodeGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/a@1", Name: "a", Version: "1"})
	g.AddNode(&graph.Node{ID: "pkg:npm/b@1", Name: "b", Version: "1"})
	return g
}

func f(node string, gc finding.GateClass) finding.Finding {
	return finding.Finding{CheckID: "T", NodeID: node, GateClass: gc, Severity: finding.SevMedium, Confidence: 1}
}

func TestAdvisoryNeverGates(t *testing.T) {
	g := twoNodeGraph()
	res := Evaluate(g, []finding.Finding{f("pkg:npm/a@1", finding.GateAdvisory)}, Policy{FailOnEligible: true})
	if res.ExitCode != ExitClean {
		t.Errorf("advisory finding gated: exit=%d, want %d", res.ExitCode, ExitClean)
	}
	if res.Risk["pkg:npm/a@1"] != finding.RiskWarned {
		t.Errorf("advisory node risk = %q, want warned", res.Risk["pkg:npm/a@1"])
	}
}

func TestGateEligibleRespectsPolicy(t *testing.T) {
	g := twoNodeGraph()
	off := Evaluate(g, []finding.Finding{f("pkg:npm/a@1", finding.GateEligible)}, Policy{FailOnEligible: false})
	if off.ExitCode != ExitClean {
		t.Errorf("eligible w/ policy off: exit=%d, want %d", off.ExitCode, ExitClean)
	}
	g2 := twoNodeGraph()
	on := Evaluate(g2, []finding.Finding{f("pkg:npm/a@1", finding.GateEligible)}, Policy{FailOnEligible: true})
	if on.ExitCode != ExitGate {
		t.Errorf("eligible w/ policy on: exit=%d, want %d", on.ExitCode, ExitGate)
	}
}

func TestBlockAlwaysGates(t *testing.T) {
	g := twoNodeGraph()
	res := Evaluate(g, []finding.Finding{f("pkg:npm/b@1", finding.GateBlock)}, Policy{FailOnEligible: false})
	if res.ExitCode != ExitBlock {
		t.Errorf("block finding: exit=%d, want %d", res.ExitCode, ExitBlock)
	}
	if res.Risk["pkg:npm/b@1"] != finding.RiskFlagged {
		t.Errorf("block node risk = %q, want flagged", res.Risk["pkg:npm/b@1"])
	}
	if res.Risk["pkg:npm/a@1"] != finding.RiskClean {
		t.Errorf("untouched node risk = %q, want clean", res.Risk["pkg:npm/a@1"])
	}
}

func TestCounts(t *testing.T) {
	g := twoNodeGraph()
	res := Evaluate(g, []finding.Finding{
		f("pkg:npm/a@1", finding.GateAdvisory),
		f("pkg:npm/a@1", finding.GateEligible),
		f("pkg:npm/b@1", finding.GateBlock),
	}, Policy{})
	if res.Counts.Total != 3 || res.Counts.Block != 1 || res.Counts.Eligible != 1 || res.Counts.Advisory != 1 {
		t.Errorf("counts = %+v", res.Counts)
	}
}
