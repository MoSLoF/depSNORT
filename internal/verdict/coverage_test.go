package verdict

import (
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// Decision D-24. Observed on a real target: redtiger-tools declares 33
// dependencies in an unpinned requirements.txt. dependaSNORT resolved exactly
// one node — the root — ran zero checks, and reported exit 0 with a PASSED
// banner. The extraction layer recorded the gap honestly; the verdict layer
// threw it away.
//
// A false alarm gets investigated. A false all-clear gets trusted. These tests
// exist so the second one cannot come back.

func rootWithUnresolved(n int) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: "pkg:pypi/redtiger-tools@0.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "redtiger-tools", Version: "0.0.0",
		Attr: map[string]string{
			graph.AttrUnresolved:      "browser-cookie3,keyboard,selenium",
			graph.AttrUnresolvedCount: itoa(n),
		},
	})
	g.Roots = []string{"pkg:pypi/redtiger-tools@0.0.0"}
	return g
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestUnresolvedDependenciesAreNeverReportedAsClean(t *testing.T) {
	g := rootWithUnresolved(33)
	res := Evaluate(g, nil, Policy{})

	if !res.Coverage.Degraded {
		t.Fatal("33 unresolved dependencies must mark coverage degraded")
	}
	if res.Coverage.Unresolved != 33 {
		t.Errorf("Unresolved = %d, want 33", res.Coverage.Unresolved)
	}
	if res.Coverage.IncompleteRoots != 1 {
		t.Errorf("IncompleteRoots = %d, want 1", res.Coverage.IncompleteRoots)
	}
	if res.Coverage.Complete {
		t.Error("Complete must be false when nothing resolved")
	}
}

// Coverage is REPORTED always and GATES only on opt-in — the same discipline as
// gate-eligible findings (D-06). Silently changing the exit code of every
// existing pipeline would be its own kind of dishonesty.
func TestDegradedCoverageDoesNotGateByDefault(t *testing.T) {
	g := rootWithUnresolved(33)
	if res := Evaluate(g, nil, Policy{}); res.ExitCode != ExitClean {
		t.Errorf("exit = %d, want %d without -fail-on-incomplete", res.ExitCode, ExitClean)
	}
	if res := Evaluate(g, nil, Policy{FailOnIncomplete: true}); res.ExitCode != ExitIncomplete {
		t.Errorf("exit = %d, want %d with -fail-on-incomplete", res.ExitCode, ExitIncomplete)
	}
}

// A poisoned package outranks an incomplete read: you act on what you found
// before you act on what you missed.
func TestBlockOutranksIncompleteCoverage(t *testing.T) {
	g := rootWithUnresolved(33)
	fs := []finding.Finding{{
		CheckID: "VC-001", Axis: finding.AxisKnownCompromise,
		Severity: finding.SevCritical, GateClass: finding.GateBlock,
		Confidence: 1, NodeID: "pkg:pypi/redtiger-tools@0.0.0", Title: "malicious",
	}}
	res := Evaluate(g, fs, Policy{FailOnIncomplete: true})
	if res.ExitCode != ExitBlock {
		t.Errorf("exit = %d, want %d — a block must outrank degraded coverage", res.ExitCode, ExitBlock)
	}
}

// A flat lockfile format is a limitation of the FORMAT, not a resolver failure.
// It must be disclosed without being treated as degradation, or every Python
// project pays a warning tax and the signal gets muted.
func TestFlatResolutionIsDisclosedButNotDegraded(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: "pkg:pypi/crimson-forge@0.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "crimson-forge", Version: "0.0.0",
		Attr: map[string]string{graph.AttrFlatResolution: "pypi"},
	})
	g.Roots = []string{"pkg:pypi/crimson-forge@0.0.0"}

	res := Evaluate(g, nil, Policy{FailOnIncomplete: true})
	if res.Coverage.Degraded {
		t.Error("a flat lockfile format is not resolver degradation")
	}
	if res.Coverage.Complete {
		t.Error("flat resolution must still prevent a claim of complete coverage")
	}
	if len(res.Coverage.FlatEcosystems) != 1 || res.Coverage.FlatEcosystems[0] != "pypi" {
		t.Errorf("FlatEcosystems = %v, want [pypi]", res.Coverage.FlatEcosystems)
	}
	if res.ExitCode != ExitClean {
		t.Errorf("exit = %d, want %d — flat resolution must not gate", res.ExitCode, ExitClean)
	}
}

func TestFullyResolvedGraphReportsCompleteCoverage(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/app@1.0.0", Kind: graph.KindPackage, Name: "app", Version: "1.0.0"})
	g.AddNode(&graph.Node{ID: "pkg:npm/dep@2.0.0", Kind: graph.KindPackage, Name: "dep", Version: "2.0.0"})
	g.AddEdge("pkg:npm/app@1.0.0", "pkg:npm/dep@2.0.0", graph.EdgeDependsOn)
	g.Roots = []string{"pkg:npm/app@1.0.0"}

	res := Evaluate(g, nil, Policy{FailOnIncomplete: true})
	if !res.Coverage.Complete || res.Coverage.Degraded {
		t.Errorf("a fully resolved graph must report complete coverage: %+v", res.Coverage)
	}
	if res.ExitCode != ExitClean {
		t.Errorf("exit = %d, want %d", res.ExitCode, ExitClean)
	}
}
