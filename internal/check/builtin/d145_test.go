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

// D-145: D-144 made the advisory list complete but left the prose SAMPLE ranked
// only when -epss was on. Without it there was no signal and ids fell in sorted
// order — which is not neutral: CVE identifiers sort chronologically, so the
// eight ids an operator actually read were reliably the OLDEST a package had,
// and because "CVE-" sorts before "GHSA-", a package with eight or more CVEs
// showed no GHSA at all.
//
// An advisory record carries no severity — OSV's querybatch returns only id and
// modified, and hydrating severity would be one request per vulnerability — but
// it does carry WHEN IT LAST CHANGED, and that was being thrown away.

const d145Pkg = "pkg:npm/widget@1.0.0"

func d145Ctx(t *testing.T, advs []datasource.Advisory) *check.Context {
	t.Helper()
	g := graph.New()
	g.AddNode(&graph.Node{ID: d145Pkg, Kind: graph.KindPackage, Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	return &check.Context{Graph: g, Advisories: map[string][]datasource.Advisory{d145Pkg: advs}}
}

func d145Year(y int) time.Time { return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC) }

// d145Stale is eight advisories last touched years ago.
func d145Stale() []datasource.Advisory {
	var out []datasource.Advisory
	for i, s := range []string{
		"CVE-2015-1000", "CVE-2015-1001", "CVE-2016-1002", "CVE-2016-1003",
		"CVE-2017-1004", "CVE-2017-1005", "CVE-2018-1006", "CVE-2018-1007",
	} {
		out = append(out, datasource.Advisory{ID: s, Source: "osv", Modified: d145Year(2015 + i/2)})
	}
	return out
}

func d145Prose(t *testing.T, ctx *check.Context) string {
	t.Helper()
	fs := (KnownVuln{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("want one aggregated finding, got %d", len(fs))
	}
	return fs[0].Evidence
}

// TestD145RecentlyModifiedSurvivesTheProseCap is the case that motivated this:
// the timestamp was present in the data and ignored.
func TestD145RecentlyModifiedSurvivesTheProseCap(t *testing.T) {
	advs := append(d145Stale(),
		datasource.Advisory{ID: "CVE-2026-9002", Source: "osv", Modified: d145Year(2026)},
		datasource.Advisory{ID: "CVE-2025-9001", Source: "osv", Modified: d145Year(2026)},
	)
	prose := d145Prose(t, d145Ctx(t, advs))
	for _, want := range []string{"CVE-2026-9002", "CVE-2025-9001"} {
		if !strings.Contains(prose, want) {
			t.Errorf("%s was modified most recently and must survive the cap: %q", want, prose)
		}
	}
	if !strings.Contains(prose, "+2 more") {
		t.Errorf("the cap should still engage and still be disclosed: %q", prose)
	}
}

// TestD145GHSAIsNoLongerSegregated: the old rule hid every GHSA behind the CVEs
// because of how the two prefixes sort, not because of anything about the
// advisories. A GHSA touched today must be able to reach the sample.
func TestD145GHSAIsNoLongerSegregated(t *testing.T) {
	advs := append(d145Stale(),
		datasource.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Source: "osv", Modified: d145Year(2026)},
	)
	if prose := d145Prose(t, d145Ctx(t, advs)); !strings.Contains(prose, "GHSA-aaaa-bbbb-cccc") {
		t.Errorf("a recently-modified GHSA must not be hidden by prefix ordering: %q", prose)
	}
}

// TestD145CVEYearIsTheFallbackWithoutTimestamps: snapshot and bundled records
// carry no Modified at all, so the year in a CVE id stands in. This is the
// offline path, and without it the whole change would only work online.
func TestD145CVEYearIsTheFallbackWithoutTimestamps(t *testing.T) {
	var advs []datasource.Advisory
	for _, s := range []string{
		"CVE-2015-1000", "CVE-2015-1001", "CVE-2016-1002", "CVE-2016-1003",
		"CVE-2017-1004", "CVE-2017-1005", "CVE-2018-1006", "CVE-2018-1007",
		"CVE-2025-9001", "CVE-2026-9002",
	} {
		advs = append(advs, datasource.Advisory{ID: s, Source: "snapshot"}) // no Modified
	}
	prose := d145Prose(t, d145Ctx(t, advs))
	for _, want := range []string{"CVE-2026-9002", "CVE-2025-9001"} {
		if !strings.Contains(prose, want) {
			t.Errorf("%s should rank first on its CVE year alone: %q", want, prose)
		}
	}
}

// TestD145RealTimestampBeatsTheYearGuess: Modified is an UPDATE date and the
// parsed year is only a DISCLOSURE year, so the two are not interchangeable.
// An old CVE the registry revised last year outranks a newer one nobody has
// touched — and would not if the fallback were allowed to override the real
// signal.
func TestD145RealTimestampBeatsTheYearGuess(t *testing.T) {
	advs := []datasource.Advisory{
		{ID: "CVE-2015-1000", Source: "osv", Modified: d145Year(2026)},
		{ID: "CVE-2024-2000", Source: "osv"}, // no timestamp: falls back to 2024
	}
	prose := d145Prose(t, d145Ctx(t, advs))
	i, j := strings.Index(prose, "CVE-2015-1000"), strings.Index(prose, "CVE-2024-2000")
	if i < 0 || j < 0 {
		t.Fatalf("both ids should appear: %q", prose)
	}
	if i > j {
		t.Errorf("the advisory with a real 2026 timestamp should lead: %q", prose)
	}
}

// TestD145EPSSStillOutranksRecency: recency is a proxy; a measured exploit
// probability is not. Adding the fallback must not demote the better signal.
func TestD145EPSSStillOutranksRecency(t *testing.T) {
	advs := append(d145Stale(),
		datasource.Advisory{ID: "CVE-2026-9002", Source: "osv", Modified: d145Year(2026)},
	)
	// The OLDEST advisory is the one under active exploitation.
	advs[0].ID = "CVE-2015-1000"
	ctx := d145Ctx(t, advs)
	ctx.EPSS = map[string]epss.Score{"CVE-2015-1000": {EPSS: 0.98, Percentile: 0.999}}
	prose := d145Prose(t, ctx)
	if !strings.HasPrefix(prose, "widget@1.0.0 is affected by CVE-2015-1000, ") {
		t.Errorf("the exploited advisory must lead regardless of age: %q", prose)
	}
}

// TestD145MalformedYearsDoNotRankFirst: an id is attacker-influenced data. A
// bogus year must not sort above every real advisory.
func TestD145MalformedYearsDoNotRankFirst(t *testing.T) {
	for _, bogus := range []string{"CVE-9999-1", "CVE-99999999-1", "CVE-notayear-1", "CVE--1"} {
		advs := append(d145Stale(), datasource.Advisory{ID: bogus, Source: "snapshot"})
		advs = append(advs, datasource.Advisory{ID: "CVE-2026-9002", Source: "osv", Modified: d145Year(2026)})
		prose := d145Prose(t, d145Ctx(t, advs))
		if !strings.HasPrefix(prose, "widget@1.0.0 is affected by CVE-2026-9002, ") {
			t.Errorf("%q outranked a genuinely recent advisory: %q", bogus, prose)
		}
	}
}

// TestD145OrderIsDeterministic: a CI gate diffs this string (D-09).
func TestD145OrderIsDeterministic(t *testing.T) {
	build := func() string {
		advs := append(d145Stale(),
			datasource.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Source: "osv", Modified: d145Year(2026)},
			datasource.Advisory{ID: "CVE-2026-9002", Source: "osv", Modified: d145Year(2026)},
		)
		return d145Prose(t, d145Ctx(t, advs))
	}
	first := build()
	for i := 0; i < 20; i++ {
		if got := build(); got != first {
			t.Fatalf("evidence is not deterministic:\n %q\n %q", first, got)
		}
	}
}
