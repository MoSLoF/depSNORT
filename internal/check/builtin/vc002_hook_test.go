package builtin

import (
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

func TestHookPresentFires(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: "pkg:npm/evil@1.0.0", Name: "evil", Version: "1.0.0",
		Attr: map[string]string{"npm.hasInstallScript": "true"},
	})
	g.AddNode(&graph.Node{ID: "pkg:npm/clean@1.0.0", Name: "clean", Version: "1.0.0"})

	findings := (HookPresent{}).Run(&check.Context{Graph: g, Now: time.Now()})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.NodeID != "pkg:npm/evil@1.0.0" {
		t.Errorf("finding on wrong node: %q", f.NodeID)
	}
	if f.GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible", f.GateClass)
	}
	if f.CheckID != "VC-002a" {
		t.Errorf("check id = %q", f.CheckID)
	}
}

func TestHookPresentQuietOnCleanTree(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/clean@1.0.0", Name: "clean", Version: "1.0.0"})
	if findings := (HookPresent{}).Run(&check.Context{Graph: g}); len(findings) != 0 {
		t.Errorf("expected no findings on clean tree, got %d", len(findings))
	}
}
