package builtin

import (
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// OPU-31 / VC-002j: escalate a load-time entry-module hook that references a
// bundled native executable (the RedC2 loader composition).

func buildLoadTimeGraph(hookEvidence, artifactEvidence string) *graph.Graph {
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:npm/loader@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "npm", Name: "loader", Version: "1.0.0",
	})
	hookID := "hook:pkg:npm/loader@1.0.0#module-load:dist/index.mjs"
	g.AddNode(&graph.Node{
		ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "npm",
		Name: "module-load:dist/index.mjs",
		Attr: map[string]string{"cap.exec": "true", "hook.evidence": hookEvidence},
	})
	g.AddEdge(pkg.ID, hookID, graph.EdgeDeclaresHook)
	if artifactEvidence != "" {
		artID := hookID + "#art"
		g.AddNode(&graph.Node{
			ID: artID, Kind: graph.KindReferencedArtifact, Ecosystem: "npm",
			Name: "math-core.bin",
			Attr: map[string]string{"cap.exec": "true", "artifact.evidence": artifactEvidence},
		})
		g.AddEdge(hookID, artID, graph.EdgeHookExecs)
	}
	return g
}

func TestVC002jFiresOnLoadTimeNativeExec(t *testing.T) {
	g := buildLoadTimeGraph("child_process,load-time-execution", "bundled-native-executable:elf")
	fs := (HookLoadTimeNativeExec{}).Run(ctx(g))
	if len(fs) != 1 {
		t.Fatalf("VC-002j: want 1 finding, got %d", len(fs))
	}
	if fs[0].CheckID != "VC-002j" {
		t.Errorf("check id = %q", fs[0].CheckID)
	}
	if fs[0].GateClass != finding.GateEligible {
		t.Errorf("gate = %q, want gate-eligible", fs[0].GateClass)
	}
	if fs[0].Severity != finding.SevHigh {
		t.Errorf("severity = %q, want high", fs[0].Severity)
	}
}

// Load-time execution WITHOUT a bundled native binary is not this check's
// business (network composition is covered by the cap-based checks).
func TestVC002jSilentWithoutBundledBinary(t *testing.T) {
	g := buildLoadTimeGraph("child_process,load-time-execution", "")
	if n := countFindings(HookLoadTimeNativeExec{}, g); n != 0 {
		t.Errorf("VC-002j must not fire without a bundled native binary, got %d", n)
	}
}

// A plain lifecycle exec hook (no load-time-execution evidence) is not VC-002j.
func TestVC002jSilentOnLifecycleHook(t *testing.T) {
	g := buildHookGraph(map[string]bool{"exec": true})
	if n := countFindings(HookLoadTimeNativeExec{}, g); n != 0 {
		t.Errorf("VC-002j must not fire on an ordinary lifecycle hook, got %d", n)
	}
}
