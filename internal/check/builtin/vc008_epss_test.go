package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/epss"
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
}

// With no EPSS data the output is unchanged (no annotation, original order).
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
}
