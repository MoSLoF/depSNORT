package builtin

import (
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

func TestOSADistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"express", "express", 0},
		{"express", "expres", 1},   // deletion
		{"express", "expresss", 1}, // insertion
		{"lodash", "lodahs", 1},    // transposition (adjacent swap)
		{"chalk", "chlak", 1},      // transposition
		{"react", "reactt", 1},
		{"", "abc", 3},
	}
	for _, c := range cases {
		if got := osaDistance(c.a, c.b); got != c.want {
			t.Errorf("osaDistance(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func npmNode(g *graph.Graph, name, ver string, attr map[string]string) {
	g.AddNode(&graph.Node{
		ID: "pkg:npm/" + name + "@" + ver, Ecosystem: "npm",
		Name: name, Version: ver, Attr: attr,
	})
}

func TestTyposquatFlagsNearMissNotExact(t *testing.T) {
	g := graph.New()
	npmNode(g, "expresss", "1.0.0", nil) // squat of express (dist 1)
	npmNode(g, "express", "4.19.2", nil) // legit -> must NOT flag
	npmNode(g, "util", "1.0.0", nil)     // len<5 -> must NOT flag

	fs := (Typosquat{}).Run(&check.Context{Graph: g})
	if len(fs) != 1 {
		t.Fatalf("VC-006 findings = %d, want 1 (%+v)", len(fs), fs)
	}
	if fs[0].NodeID != "pkg:npm/expresss@1.0.0" {
		t.Errorf("flagged wrong node: %s", fs[0].NodeID)
	}
	if fs[0].GateClass != finding.GateAdvisory {
		t.Errorf("typosquat must be advisory (never gates), got %s", fs[0].GateClass)
	}
}

func TestDependencyConfusionNoopWithoutConfig(t *testing.T) {
	g := graph.New()
	npmNode(g, "@ihbv/secrets", "1.0.0", map[string]string{"npm.resolved": "https://registry.npmjs.org/@ihbv/secrets/-/secrets-1.0.0.tgz"})
	if fs := (DependencyConfusion{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("VC-007 must be a no-op with no internal scopes, got %d", len(fs))
	}
}

func TestDependencyConfusionFlagsInternalOnPublic(t *testing.T) {
	g := graph.New()
	npmNode(g, "@ihbv/secrets", "1.0.0", map[string]string{"npm.resolved": "https://registry.npmjs.org/@ihbv/secrets/-/secrets-1.0.0.tgz"})
	npmNode(g, "@ihbv/internal-ok", "1.0.0", map[string]string{"npm.resolved": "https://npm.ihbv.io/@ihbv/internal-ok/-/internal-ok-1.0.0.tgz"})

	ctx := &check.Context{Graph: g, Config: check.Config{InternalScopes: []string{"@ihbv"}}}
	fs := (DependencyConfusion{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("VC-007 findings = %d, want 1 (only the public-resolved one)", len(fs))
	}
	if fs[0].NodeID != "pkg:npm/@ihbv/secrets@1.0.0" {
		t.Errorf("flagged wrong node: %s", fs[0].NodeID)
	}
	if fs[0].GateClass != finding.GateEligible {
		t.Errorf("dep-confusion should be gate-eligible, got %s", fs[0].GateClass)
	}
}
