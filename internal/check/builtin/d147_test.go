package builtin

import (
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/epss"
	"ihbv.io/depsnort/internal/graph"
)

// D-147: D-145 recorded severity as unavailable and ranked on recency instead.
// That was true of OSV's querybatch and false of /v1/query, which D-146 was
// already calling. Severity now sits between exploit probability and recency:
// how likely it is to be exploited, then how bad it is, then how fresh.

func d147Ctx(t *testing.T, advs []datasource.Advisory) *check.Context {
	t.Helper()
	id := "pkg:npm/widget@1.0.0"
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	return &check.Context{Graph: g, Advisories: map[string][]datasource.Advisory{id: advs}}
}

func d147Prose(t *testing.T, ctx *check.Context) string {
	t.Helper()
	fs := (KnownVuln{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %d", len(fs))
	}
	return fs[0].Evidence
}

func d147Scored(id string, score float64) datasource.Advisory {
	return datasource.Advisory{ID: id, Source: "osv", Severity: score, ScoredSeverity: true}
}

// d147Filler is eight recent-but-unrated advisories: without severity they would
// all outrank an older critical one on D-145's recency signal alone.
func d147Filler() []datasource.Advisory {
	var out []datasource.Advisory
	for _, id := range []string{
		"CVE-2026-8001", "CVE-2026-8002", "CVE-2026-8003", "CVE-2026-8004",
		"CVE-2026-8005", "CVE-2026-8006", "CVE-2026-8007", "CVE-2026-8008",
	} {
		out = append(out, datasource.Advisory{
			ID: id, Source: "osv",
			Modified: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		})
	}
	return out
}

// TestD147SeverityOutranksRecency is the change itself: a 2015 critical beats
// eight unrated advisories from this year.
func TestD147SeverityOutranksRecency(t *testing.T) {
	advs := append(d147Filler(), d147Scored("CVE-2015-1000", 9.8))
	prose := d147Prose(t, d147Ctx(t, advs))
	if !strings.HasPrefix(prose, "widget@1.0.0 is affected by CVE-2015-1000, ") {
		t.Errorf("the critical advisory must lead regardless of age: %q", prose)
	}
}

// TestD147EPSSStillOutranksSeverity: severity is impact, EPSS is a measured
// probability of exploitation. D-145 put the measured signal first and D-147
// slots in beneath it, not above.
func TestD147EPSSStillOutranksSeverity(t *testing.T) {
	advs := []datasource.Advisory{
		d147Scored("CVE-2020-CRIT", 9.8),
		{ID: "CVE-2020-LOW", Source: "osv", Severity: 3.1, ScoredSeverity: true},
	}
	ctx := d147Ctx(t, advs)
	ctx.EPSS = map[string]epss.Score{"CVE-2020-LOW": {EPSS: 0.97, Percentile: 0.999}}
	prose := d147Prose(t, ctx)
	if !strings.HasPrefix(prose, "widget@1.0.0 is affected by CVE-2020-LOW, ") {
		t.Errorf("the advisory under active exploitation must lead: %q", prose)
	}
}

// TestD147TierBeatsRawScoreAcrossSources is the reason ranking is by tier first.
// A label-only CRITICAL and a scored 7.0 HIGH are not comparable as numbers —
// the label has no number at all — so the CVSS band is the common currency.
func TestD147TierBeatsRawScoreAcrossSources(t *testing.T) {
	advs := []datasource.Advisory{
		d147Scored("CVE-2020-HIGH", 8.9),
		{ID: "GHSA-critical", Source: "osv", SeverityLabel: "CRITICAL"},
	}
	prose := d147Prose(t, d147Ctx(t, advs))
	if !strings.HasPrefix(prose, "widget@1.0.0 is affected by GHSA-critical, ") {
		t.Errorf("a CRITICAL label outranks a HIGH score: %q", prose)
	}
}

// TestD147ScoreRefinesWithinATier: two HIGHs order by their exact scores.
func TestD147ScoreRefinesWithinATier(t *testing.T) {
	advs := []datasource.Advisory{
		d147Scored("CVE-2020-A", 7.1),
		d147Scored("CVE-2020-B", 8.8),
	}
	prose := d147Prose(t, d147Ctx(t, advs))
	if !strings.HasPrefix(prose, "widget@1.0.0 is affected by CVE-2020-B, ") {
		t.Errorf("8.8 outranks 7.1 inside the HIGH band: %q", prose)
	}
}

// TestD147ScoredZeroIsRatedNotUnknown: a vector describing no impact is a real
// rating. It must rank below every rated advisory and ABOVE an unrated one,
// because "we know it is harmless" is more than "we know nothing".
func TestD147ScoredZeroIsRatedNotUnknown(t *testing.T) {
	// The unrated advisory is named so it sorts FIRST: with both at the same
	// year and no other signal the sorted tie-break would put it in front, so
	// only the severity tier can produce the expected order. The first cut of
	// this test had the names the other way round and passed against a mutation
	// that treated a scored 0.0 as unknown — alphabetical luck standing in for
	// the behaviour under test.
	advs := []datasource.Advisory{
		{ID: "CVE-2020-AAA-UNRATED", Source: "osv"},
		{ID: "CVE-2020-ZZZ-NONE", Source: "osv", Severity: 0, ScoredSeverity: true},
	}
	prose := d147Prose(t, d147Ctx(t, advs))
	if !strings.HasPrefix(prose, "widget@1.0.0 is affected by CVE-2020-ZZZ-NONE, ") {
		t.Errorf("a scored 0.0 is rated and outranks an unrated advisory: %q", prose)
	}
}

// TestD147TierBoundaries walks the CVSS bands at their published edges.
func TestD147TierBoundaries(t *testing.T) {
	for _, tc := range []struct {
		score float64
		tier  int
	}{
		{10.0, 5}, {9.0, 5}, {8.9, 4}, {7.0, 4},
		{6.9, 3}, {4.0, 3}, {3.9, 2}, {0.1, 2}, {0.0, 1},
	} {
		got := severityTier(datasource.Advisory{Severity: tc.score, ScoredSeverity: true})
		if got != tc.tier {
			t.Errorf("score %.1f: tier %d, want %d", tc.score, got, tc.tier)
		}
	}
	for label, want := range map[string]int{
		"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "MODERATE": 3,
		"LOW": 2, "NONE": 1, "": 0, "nonsense": 0,
	} {
		if got := severityTier(datasource.Advisory{SeverityLabel: label}); got != want {
			t.Errorf("label %q: tier %d, want %d", label, got, want)
		}
	}
}

// TestD147UnratedAdvisoriesStillFallBackToRecency: severity is a new tier ABOVE
// recency, not a replacement. With nothing rated, D-145's behaviour must stand.
func TestD147UnratedAdvisoriesStillFallBackToRecency(t *testing.T) {
	advs := []datasource.Advisory{
		{ID: "CVE-2015-1000", Source: "osv"},
		{ID: "CVE-2026-9002", Source: "osv"},
	}
	prose := d147Prose(t, d147Ctx(t, advs))
	if !strings.HasPrefix(prose, "widget@1.0.0 is affected by CVE-2026-9002, ") {
		t.Errorf("with no severity anywhere, recency still decides: %q", prose)
	}
}

// TestD147PeakSeverityTravelsWithTheFinding: the number that decided the order
// has to be readable, or this repeats the D-144 complaint one field along.
func TestD147PeakSeverityTravelsWithTheFinding(t *testing.T) {
	advs := []datasource.Advisory{
		d147Scored("CVE-2020-A", 4.2),
		d147Scored("CVE-2020-CRIT", 9.8),
	}
	f := (KnownVuln{}).Run(d147Ctx(t, advs))[0]
	if f.Severity_ == nil {
		t.Fatal("a rated finding must carry its peak severity")
	}
	if f.Severity_.Peak != 9.8 || !f.Severity_.Scored {
		t.Errorf("peak should be the 9.8, got %+v", f.Severity_)
	}
	if f.Severity_.Advisory != "CVE-2020-CRIT" {
		t.Errorf("peak should name its advisory, got %q", f.Severity_.Advisory)
	}
}

// TestD147NoSeverityIsNoField: the common case before hydration, and offline.
func TestD147NoSeverityIsNoField(t *testing.T) {
	f := (KnownVuln{}).Run(d147Ctx(t, []datasource.Advisory{{ID: "CVE-2020-1"}}))[0]
	if f.Severity_ != nil {
		t.Errorf("no severity anywhere should leave the field nil, got %+v", f.Severity_)
	}
}
