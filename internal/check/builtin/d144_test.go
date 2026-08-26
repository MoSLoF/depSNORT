package builtin

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/epss"
	"ihbv.io/depsnort/internal/graph"
)

// D-144: VC-008 aggregates a package's advisories into one finding and spells a
// bounded sample into the evidence prose. The count was honest ("11 known
// vulnerabilities") and the truncation was signposted ("+3 more"), but the ids
// past the cap existed in NO output format — not JSON, not SARIF, not the PDF.
// The report told an operator that three more advisories applied and gave them
// no way to learn which.
//
// The selection rule made it worse. Ids were cut from sorted order, and CVE ids
// sort chronologically, so the sample was the eight OLDEST advisories and the
// newest were exactly the ones hidden; a package with eight or more CVEs also
// hid every GHSA, since "CVE-" sorts before "GHSA-".

func d144Node(t *testing.T, ids ...string) *check.Context {
	t.Helper()
	id := "pkg:npm/widget@1.0.0"
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	var advs []datasource.Advisory
	for _, s := range ids {
		advs = append(advs, datasource.Advisory{ID: s, Source: "osv", Malicious: datasource.ClassifyMalicious(s)})
	}
	return &check.Context{Graph: g, Advisories: map[string][]datasource.Advisory{id: advs}}
}

// d144Old is ten advisories whose sorted order puts the two newest CVEs and the
// GHSA past an eight-item cap.
var d144Old = []string{
	"CVE-2015-1000", "CVE-2015-1001", "CVE-2016-1002", "CVE-2016-1003",
	"CVE-2017-1004", "CVE-2017-1005", "CVE-2018-1006", "CVE-2018-1007",
	"CVE-2025-9001", "CVE-2026-9002", "GHSA-aaaa-bbbb-cccc",
}

func TestD144EveryAdvisoryIDSurvivesTheProseCap(t *testing.T) {
	fs := (KnownVuln{}).Run(d144Node(t, d144Old...))
	if len(fs) != 1 {
		t.Fatalf("want one aggregated finding, got %d", len(fs))
	}
	f := fs[0]
	if !strings.Contains(f.Evidence, "+3 more") {
		t.Fatalf("precondition: the prose cap should have engaged; got %q", f.Evidence)
	}
	if len(f.Advisories) != len(d144Old) {
		t.Fatalf("Advisories = %d ids, want all %d", len(f.Advisories), len(d144Old))
	}
	// The ones the prose dropped are the point of the field. Which ids those
	// are is the ranking's business and changed in D-145, so this asks the
	// question generically rather than naming ids: whatever the prose left out
	// must still be recoverable.
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	dropped := 0
	for _, id := range d144Old {
		if strings.Contains(f.Evidence, id) {
			continue
		}
		dropped++
		if !strings.Contains(string(raw), id) {
			t.Errorf("%s was dropped from the prose and is unrecoverable from the finding: %s", id, raw)
		}
	}
	if dropped != 3 {
		t.Errorf("expected 3 ids past the cap, found %d", dropped)
	}
}

// TestD144AdvisoriesAreSortedAndComplete pins the contract the field documents:
// EVERY id, in a deterministic order, regardless of how the prose was ranked.
func TestD144AdvisoriesAreSortedAndComplete(t *testing.T) {
	f := (KnownVuln{}).Run(d144Node(t, d144Old...))[0]
	// Completeness is asserted before sortedness on purpose: a sortedness loop
	// over an empty slice passes trivially, so without this the test stayed
	// green against a mutation that populated nothing at all.
	if len(f.Advisories) != len(d144Old) {
		t.Fatalf("Advisories = %d ids, want all %d", len(f.Advisories), len(d144Old))
	}
	for i := 1; i < len(f.Advisories); i++ {
		if f.Advisories[i-1] >= f.Advisories[i] {
			t.Fatalf("Advisories must be sorted; %q >= %q", f.Advisories[i-1], f.Advisories[i])
		}
	}
}

// TestD144EqualScoresKeepSortedOrder pins the tie-break the ranker documents.
// Ranking by score alone leaves every equal-scored id's position to the sort's
// discretion; the comparator must be a strict ordering so sorted order survives
// as the tie-break, which is what makes the evidence string diffable in a CI
// gate (D-09).
func TestD144EqualScoresKeepSortedOrder(t *testing.T) {
	ctx := d144Node(t, d144Old...)
	// Every id scored identically AND stamped with the same Modified: with both
	// ranking signals level, nothing but the final tie-break decides the order.
	// D-145 inserted recency between EPSS and the tie-break, so flattening it
	// here is what keeps this test about the tie-break rather than about
	// whichever signal happens to dominate.
	ctx.EPSS = map[string]epss.Score{}
	for _, id := range d144Old {
		if strings.HasPrefix(id, "CVE-") {
			ctx.EPSS[id] = epss.Score{EPSS: 0.5, Percentile: 0.5}
		}
	}
	same := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range ctx.Advisories["pkg:npm/widget@1.0.0"] {
		ctx.Advisories["pkg:npm/widget@1.0.0"][i].Modified = same
	}
	f := (KnownVuln{}).Run(ctx)[0]
	var want []string
	for _, id := range d144Old {
		if strings.HasPrefix(id, "CVE-") {
			want = append(want, id)
		}
	}
	sort.Strings(want)
	got := strings.SplitN(strings.TrimPrefix(f.Evidence, "widget@1.0.0 is affected by "), ", +", 2)[0]
	if !strings.HasPrefix(got, strings.Join(want[:maxListedAdvisories], ", ")) {
		t.Errorf("equal scores must fall back to sorted order:\n got  %q\n want %q",
			got, strings.Join(want[:maxListedAdvisories], ", "))
	}
}

// TestD144ShortListIsCarriedToo is the boundary: the field is the complete set,
// not a spillover bucket that only fills once the cap engages.
func TestD144ShortListIsCarriedToo(t *testing.T) {
	f := (KnownVuln{}).Run(d144Node(t, "CVE-2020-1", "CVE-2020-2"))[0]
	if strings.Contains(f.Evidence, "more") {
		t.Fatalf("precondition: the cap must NOT have engaged; got %q", f.Evidence)
	}
	if len(f.Advisories) != 2 {
		t.Errorf("Advisories = %v, want both ids even when nothing was truncated", f.Advisories)
	}
}

// TestD144MaliciousStayExcluded guards the filter the new field could have
// quietly widened: a MAL- advisory is VC-001's, and must not reach VC-008's
// complete list either.
func TestD144MaliciousStayExcluded(t *testing.T) {
	f := (KnownVuln{}).Run(d144Node(t, "CVE-2020-1", "MAL-2024-9999"))[0]
	for _, id := range f.Advisories {
		if strings.HasPrefix(id, "MAL-") {
			t.Errorf("malicious advisory leaked into VC-008: %v", f.Advisories)
		}
	}
	if !strings.Contains(f.Title, "1 known vulnerability") {
		t.Errorf("count should exclude the malicious advisory: %q", f.Title)
	}
}

// TestD144EPSSOrdersTheProseSample: with exploit-probability present, the ids
// the prose keeps are the ones most likely to be exploited — not the ones that
// happen to sort first. CVE-2026-9002 sorts LAST and must still be shown.
func TestD144EPSSOrdersTheProseSample(t *testing.T) {
	ctx := d144Node(t, d144Old...)
	ctx.EPSS = map[string]epss.Score{
		"CVE-2026-9002": {EPSS: 0.97, Percentile: 0.999},
		"CVE-2025-9001": {EPSS: 0.81, Percentile: 0.99},
	}
	f := (KnownVuln{}).Run(ctx)[0]
	for _, want := range []string{"CVE-2026-9002", "CVE-2025-9001"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("the highest-scoring advisory must survive the prose cap; %s missing from %q", want, f.Evidence)
		}
	}
	if !strings.Contains(f.Evidence, "+3 more") {
		t.Errorf("the cap should still engage and still be disclosed: %q", f.Evidence)
	}
}

// TestD144WithoutEPSSOrderStaysDeterministic: whatever ranks the sample, a CI
// gate diffs this string, so repeated runs over identical input must produce it
// identically (D-09).
//
// The order this asserts changed in D-145. It used to require sorted order,
// which for CVE ids means chronological, which meant the sample was reliably
// the OLDEST advisories a package had — the behaviour D-145 replaced with
// recency ranking. The determinism requirement is untouched.
func TestD144WithoutEPSSOrderStaysDeterministic(t *testing.T) {
	first := (KnownVuln{}).Run(d144Node(t, d144Old...))[0].Evidence
	for i := 0; i < 20; i++ {
		if got := (KnownVuln{}).Run(d144Node(t, d144Old...))[0].Evidence; got != first {
			t.Fatalf("evidence is not deterministic:\n %q\n %q", first, got)
		}
	}
	if !strings.Contains(first, "CVE-2026-9002, CVE-2025-9001") {
		t.Errorf("without EPSS the sample should lead with the most recent: %q", first)
	}
}
