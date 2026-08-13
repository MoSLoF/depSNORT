package verdict

import (
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// Finding F-02. graph.Coverage() only knows what the GRAPH knows: unresolved
// dependencies and orphaned nodes. It cannot see an empty OSV cache, a dead
// registry, an unreadable install surface, or a workspace project that never
// resolved — those gaps live in the CLI, above the graph. Before F-02 they were
// warned to stderr and dropped on the floor, so -fail-on-incomplete could return
// a clean 0 over a scan that barely looked. These tests pin each gap class to
// exit 3, and pin the two invariants that keep the fix honest: it only gates on
// opt-in, and a block always outranks it.

// resolvedGraph is a small, fully-resolved graph: complete coverage, nothing
// degraded, so any incompleteness in a test below comes purely from the
// scan-level gap that test injects — never from the graph.
func resolvedGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/app@1.0.0", Kind: graph.KindPackage, Name: "app", Version: "1.0.0"})
	g.AddNode(&graph.Node{ID: "pkg:npm/dep@2.0.0", Kind: graph.KindPackage, Name: "dep", Version: "2.0.0"})
	g.AddEdge("pkg:npm/app@1.0.0", "pkg:npm/dep@2.0.0", graph.EdgeDependsOn)
	g.Roots = []string{"pkg:npm/app@1.0.0"}
	return g
}

// assertGates checks that a given scan-level coverage is inert without opt-in and
// returns exit 3 with it — the whole contract of F-02 in one helper.
func assertGates(t *testing.T, g *graph.Graph, cov graph.Coverage, what string) {
	t.Helper()
	if cov.Degraded {
		t.Fatalf("%s: precondition failed — the graph itself is degraded, so this "+
			"would pass even without the F-02 fix", what)
	}
	if !cov.Incomplete() {
		t.Fatalf("%s: must make coverage incomplete", what)
	}
	if res := EvaluateWithCoverage(g, nil, cov, Policy{}); res.ExitCode != ExitClean {
		t.Errorf("%s: without -fail-on-incomplete exit = %d, want %d (report, do not gate)",
			what, res.ExitCode, ExitClean)
	}
	if res := EvaluateWithCoverage(g, nil, cov, Policy{FailOnIncomplete: true}); res.ExitCode != ExitIncomplete {
		t.Errorf("%s: with -fail-on-incomplete exit = %d, want %d", what, res.ExitCode, ExitIncomplete)
	}
}

func TestEmptyOSVCacheGatesIncomplete(t *testing.T) {
	g := resolvedGraph()
	cov := g.Coverage()
	cov.DataSourceGaps = []string{"osv"} // offline miss / empty cache -> Stats.Gaps>0
	assertGates(t, g, cov, "an offline empty OSV cache")
}

func TestRegistryTransportFailureGatesIncomplete(t *testing.T) {
	g := resolvedGraph()
	cov := g.Coverage()
	cov.DataSourceGaps = []string{"npm"} // a registry source that errored
	assertGates(t, g, cov, "a registry transport failure")
}

func TestInstallSurfaceExtractorGapGatesIncomplete(t *testing.T) {
	g := resolvedGraph()
	cov := g.Coverage()
	cov.ExtractorGaps = 1 // an install-surface extraction that failed
	assertGates(t, g, cov, "a partial install-surface extraction")
}

func TestFailedWorkspaceProjectGatesIncomplete(t *testing.T) {
	g := resolvedGraph()
	cov := g.Coverage()
	cov.FailedProjects = 1 // a project under -recursive that did not resolve
	assertGates(t, g, cov, "a failed workspace project")
}

// A scan-level gap is subject to the same opt-in discipline as graph degradation:
// it is always reported, and gates only when the operator asked it to.
func TestScanLevelGapDoesNotGateByDefault(t *testing.T) {
	g := resolvedGraph()
	cov := g.Coverage()
	cov.DataSourceGaps = []string{"osv"}
	cov.ExtractorGaps = 2
	cov.FailedProjects = 1
	if res := EvaluateWithCoverage(g, nil, cov, Policy{}); res.ExitCode != ExitClean {
		t.Errorf("exit = %d, want %d — scan-level gaps must not gate without opt-in", res.ExitCode, ExitClean)
	}
}

// You act on what you found before you act on what you missed: a block-class
// finding outranks an incomplete read, scan-level or otherwise.
func TestBlockOutranksScanLevelGap(t *testing.T) {
	g := resolvedGraph()
	cov := g.Coverage()
	cov.DataSourceGaps = []string{"osv"}
	cov.FailedProjects = 1
	fs := []finding.Finding{{
		CheckID: "VC-001", Axis: finding.AxisKnownCompromise,
		Severity: finding.SevCritical, GateClass: finding.GateBlock,
		Confidence: 1, NodeID: "pkg:npm/dep@2.0.0", Title: "malicious",
	}}
	res := EvaluateWithCoverage(g, fs, cov, Policy{FailOnIncomplete: true})
	if res.ExitCode != ExitBlock {
		t.Errorf("exit = %d, want %d — a block must outrank incomplete coverage", res.ExitCode, ExitBlock)
	}
}

// The negative control: no gaps of any kind, opted in, must still be clean — so
// the aggregate can't be firing on an always-true condition.
func TestNoGapsStaysCleanEvenOptedIn(t *testing.T) {
	g := resolvedGraph()
	cov := g.Coverage()
	if cov.Incomplete() {
		t.Fatalf("a fully resolved graph with no scan gaps must be complete: %+v", cov)
	}
	if res := EvaluateWithCoverage(g, nil, cov, Policy{FailOnIncomplete: true}); res.ExitCode != ExitClean {
		t.Errorf("exit = %d, want %d", res.ExitCode, ExitClean)
	}
}
