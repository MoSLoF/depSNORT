package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/epss"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// EPSS enrichment must (a) annotate each VC-008 finding with the peak exploit
// probability across its CVEs — mapping GHSA/GO advisories through their CVE
// aliases — and (b) order findings so the highest-EPSS package surfaces first.
func TestVC008EPSSAnnotatesAndRanks(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/low@1", Name: "low", Version: "1", Ecosystem: "npm", Kind: graph.KindPackage})
	g.AddNode(&graph.Node{ID: "pkg:npm/high@1", Name: "high", Version: "1", Ecosystem: "npm", Kind: graph.KindPackage})

	ctx := &check.Context{
		Graph: g,
		Advisories: map[string][]datasource.Advisory{
			// low: a CVE-primary advisory, small EPSS
			"pkg:npm/low@1": {{ID: "CVE-2020-1111"}},
			// high: a GHSA-primary advisory whose CVE alias carries a big EPSS
			"pkg:npm/high@1": {{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2021-44228"}}},
		},
		EPSS: map[string]epss.Score{
			"CVE-2020-1111":  {EPSS: 0.02, Percentile: 0.40},
			"CVE-2021-44228": {EPSS: 0.99999, Percentile: 1.0},
		},
	}

	out := KnownVuln{}.Run(ctx)
	if len(out) != 2 {
		t.Fatalf("want 2 findings, got %d", len(out))
	}
	// (b) ranking: high-EPSS package first.
	if out[0].NodeID != "pkg:npm/high@1" {
		t.Errorf("highest-EPSS package must rank first, got %s", out[0].NodeID)
	}
	// (a) annotation: peak EPSS present, resolved through the GHSA->CVE alias.
	if !strings.Contains(out[0].Evidence, "peak EPSS 1.000") || !strings.Contains(out[0].Evidence, "CVE-2021-44228") {
		t.Errorf("high finding missing peak EPSS via alias: %q", out[0].Evidence)
	}
	if !strings.Contains(out[1].Evidence, "peak EPSS 0.020") {
		t.Errorf("low finding missing peak EPSS: %q", out[1].Evidence)
	}
	// (c) structured field: consumers get the peak as data, not only prose.
	if out[0].EPSS == nil || out[0].EPSS.CVE != "CVE-2021-44228" || out[0].EPSS.Peak != 0.99999 {
		t.Errorf("high finding structured EPSS wrong: %+v", out[0].EPSS)
	}
	if out[1].EPSS == nil || out[1].EPSS.Peak != 0.02 {
		t.Errorf("low finding structured EPSS wrong: %+v", out[1].EPSS)
	}
	// Enrichment alone must NOT gate — that is -epss-gate's job.
	for _, f := range out {
		if f.GateClass != finding.GateAdvisory {
			t.Errorf("EPSS annotation without -epss-gate must stay advisory, got %s on %s", f.GateClass, f.NodeID)
		}
	}
}

// With no EPSS data the output is unchanged (no annotation, no structured field,
// original order).
func TestVC008NoEPSSIsUnchanged(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/a@1", Name: "a", Version: "1", Ecosystem: "npm", Kind: graph.KindPackage})
	ctx := &check.Context{
		Graph:      g,
		Advisories: map[string][]datasource.Advisory{"pkg:npm/a@1": {{ID: "CVE-2020-1111"}}},
	}
	out := KnownVuln{}.Run(ctx)
	if len(out) != 1 || strings.Contains(out[0].Evidence, "EPSS") {
		t.Errorf("no-EPSS run must not annotate: %q", out[0].Evidence)
	}
	if out[0].EPSS != nil {
		t.Errorf("no-EPSS run must not set the structured field: %+v", out[0].EPSS)
	}
}

// Gating posture: with -epss-gate set, only findings whose peak EPSS meets the
// threshold escalate from advisory to gate-eligible; the rest stay advisory.
func TestVC008EPSSGateEscalatesOnlyAboveThreshold(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/quiet@1", Name: "quiet", Version: "1", Ecosystem: "npm", Kind: graph.KindPackage})
	g.AddNode(&graph.Node{ID: "pkg:npm/hot@1", Name: "hot", Version: "1", Ecosystem: "npm", Kind: graph.KindPackage})
	ctx := &check.Context{
		Graph: g,
		Advisories: map[string][]datasource.Advisory{
			"pkg:npm/quiet@1": {{ID: "CVE-2020-1111"}},
			"pkg:npm/hot@1":   {{ID: "CVE-2021-44228"}},
		},
		EPSS: map[string]epss.Score{
			"CVE-2020-1111":  {EPSS: 0.10, Percentile: 0.50},
			"CVE-2021-44228": {EPSS: 0.90, Percentile: 0.99},
		},
		EPSSGate: 0.5,
	}
	byNode := map[string]finding.Finding{}
	for _, f := range (KnownVuln{}).Run(ctx) {
		byNode[f.NodeID] = f
	}
	if got := byNode["pkg:npm/hot@1"]; got.GateClass != finding.GateEligible {
		t.Errorf("peak 0.90 >= 0.5 threshold must escalate to gate-eligible, got %s", got.GateClass)
	} else if !strings.Contains(got.Evidence, "gate-eligible") {
		t.Errorf("escalated finding must record the reason in evidence: %q", got.Evidence)
	}
	if got := byNode["pkg:npm/quiet@1"]; got.GateClass != finding.GateAdvisory {
		t.Errorf("peak 0.10 < 0.5 threshold must stay advisory, got %s", got.GateClass)
	}
}

// The threshold is inclusive at its boundary (>=), and a finding exactly at the
// threshold escalates.
func TestVC008EPSSGateBoundaryIsInclusive(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/edge@1", Name: "edge", Version: "1", Ecosystem: "npm", Kind: graph.KindPackage})
	ctx := &check.Context{
		Graph:      g,
		Advisories: map[string][]datasource.Advisory{"pkg:npm/edge@1": {{ID: "CVE-2021-44228"}}},
		EPSS:       map[string]epss.Score{"CVE-2021-44228": {EPSS: 0.5, Percentile: 0.9}},
		EPSSGate:   0.5,
	}
	out := KnownVuln{}.Run(ctx)
	if len(out) != 1 || out[0].GateClass != finding.GateEligible {
		t.Errorf("peak exactly at threshold must escalate (>=), got %+v", out)
	}
}
