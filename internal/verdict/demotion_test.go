package verdict

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

func oneNode(id string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Name: "p", Version: "1"})
	return g
}

// The live-run regression: a real but ancient release burst must not fail a
// build today just because -fail-on-eligible is set.
func TestStaleTemporalFindingCannotGate(t *testing.T) {
	id := "pkg:npm/tar@4.4.13"
	g := oneNode(id)
	res := Evaluate(g, []finding.Finding{{
		CheckID: "VC-005", Axis: finding.AxisWeather, Severity: finding.SevMedium,
		GateClass: finding.GateEligible, Confidence: 0.6,
		RecencyDecay: 0.0001, // ~7 years old
		NodeID:       id, Title: "release burst", Evidence: "4 releases in 1d",
	}}, Policy{FailOnEligible: true})

	if res.ExitCode != ExitClean {
		t.Errorf("stale temporal finding gated the build: exit=%d, want %d", res.ExitCode, ExitClean)
	}
	if res.Counts.Advisory != 1 || res.Counts.Eligible != 0 {
		t.Errorf("counts = %+v, want it recounted as advisory", res.Counts)
	}
	// Demotion must be disclosed, not silent.
	if !strings.Contains(res.Findings[0].Evidence, "demoted to advisory") {
		t.Errorf("demotion not recorded in evidence: %q", res.Findings[0].Evidence)
	}
	// It must still be visible — demoted, never dropped.
	if len(res.Findings) != 1 {
		t.Errorf("finding was dropped instead of demoted")
	}
}

func TestFreshTemporalFindingStillGates(t *testing.T) {
	id := "pkg:npm/evil@1.0.0"
	g := oneNode(id)
	res := Evaluate(g, []finding.Finding{{
		CheckID: "VC-005", GateClass: finding.GateEligible, Confidence: 0.8,
		RecencyDecay: 0.97, // days old
		NodeID:       id,
	}}, Policy{FailOnEligible: true})

	if res.ExitCode != ExitGate {
		t.Errorf("fresh temporal finding should gate: exit=%d, want %d", res.ExitCode, ExitGate)
	}
}

func TestBlockIsNeverDemotedByAge(t *testing.T) {
	id := "pkg:npm/poisoned@1.0.0"
	g := oneNode(id)
	res := Evaluate(g, []finding.Finding{{
		CheckID: "VC-001", GateClass: finding.GateBlock, Confidence: 1,
		RecencyDecay: 0.00001, // ancient
		NodeID:       id,
	}}, Policy{})

	if res.ExitCode != ExitBlock {
		t.Errorf("a poisoned release does not become safe with age: exit=%d", res.ExitCode)
	}
	if res.Counts.Block != 1 {
		t.Errorf("block finding was demoted: %+v", res.Counts)
	}
}

func TestNonTemporalEligibleUnaffected(t *testing.T) {
	id := "pkg:npm/hooky@1.0.0"
	g := oneNode(id)
	// No RecencyDecay set (0) -> not a temporal finding -> never demoted.
	res := Evaluate(g, []finding.Finding{{
		CheckID: "VC-002d", GateClass: finding.GateEligible, Confidence: 0.5, NodeID: id,
	}}, Policy{FailOnEligible: true})

	if res.ExitCode != ExitGate {
		t.Errorf("non-temporal finding should be unaffected by decay logic: exit=%d", res.ExitCode)
	}
}
