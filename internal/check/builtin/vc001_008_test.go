package builtin

import (
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

func graphWithNode(id, name, ver string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Name: name, Version: ver, Ecosystem: "npm"})
	return g
}

func TestVC001FlagsMalicious(t *testing.T) {
	id := "pkg:npm/evil@1.0.0"
	g := graphWithNode(id, "evil", "1.0.0")
	ctx := &check.Context{Graph: g, Advisories: map[string][]datasource.Advisory{
		id: {{ID: "MAL-2026-1", Malicious: true, Source: "osv"}},
	}}
	fs := (MaliciousVersion{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("VC-001 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass != finding.GateBlock || fs[0].Severity != finding.SevCritical {
		t.Errorf("VC-001 finding = %+v", fs[0])
	}

	// End-to-end: a malicious finding must force exit 1 and flag the node.
	res := verdict.Evaluate(g, fs, verdict.Policy{})
	if res.ExitCode != verdict.ExitBlock {
		t.Errorf("exit code = %d, want %d", res.ExitCode, verdict.ExitBlock)
	}
	if res.Risk[id] != finding.RiskFlagged {
		t.Errorf("node risk = %q, want flagged", res.Risk[id])
	}
}

func TestVC008ReportsVulnAsAdvisory(t *testing.T) {
	id := "pkg:npm/vulnerable@2.0.0"
	g := graphWithNode(id, "vulnerable", "2.0.0")
	ctx := &check.Context{Graph: g, Advisories: map[string][]datasource.Advisory{
		id: {{ID: "CVE-2025-1", Malicious: false, Source: "osv"}},
	}}
	fs := (KnownVuln{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("VC-008 findings = %d, want 1", len(fs))
	}
	if fs[0].Axis != finding.AxisVuln || fs[0].GateClass != finding.GateAdvisory {
		t.Errorf("VC-008 finding = %+v", fs[0])
	}

	// A CVE alone must NOT gate (advisory never gates).
	res := verdict.Evaluate(g, fs, verdict.Policy{FailOnEligible: true})
	if res.ExitCode != verdict.ExitClean {
		t.Errorf("CVE gated the build: exit=%d, want %d", res.ExitCode, verdict.ExitClean)
	}
}

func TestVC001IgnoresNonMaliciousAndVC008IgnoresMalicious(t *testing.T) {
	id := "pkg:npm/mixed@1.2.3"
	g := graphWithNode(id, "mixed", "1.2.3")
	adv := map[string][]datasource.Advisory{id: {
		{ID: "MAL-2026-2", Malicious: true},
		{ID: "CVE-2025-2", Malicious: false},
	}}
	ctx := &check.Context{Graph: g, Advisories: adv}
	if got := len((MaliciousVersion{}).Run(ctx)); got != 1 {
		t.Errorf("VC-001 should see only the malicious advisory, got %d", got)
	}
	if got := len((KnownVuln{}).Run(ctx)); got != 1 {
		t.Errorf("VC-008 should see only the CVE, got %d", got)
	}
}
