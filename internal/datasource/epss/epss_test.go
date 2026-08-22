package epss

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// fakeDoer serves canned EPSS envelopes and records how many CVEs each call
// requested, so batching/chunking can be asserted.
type fakeDoer struct {
	scores    map[string]Score // CVE -> score the "API" knows
	callCVEs  [][]string       // CVEs requested per call
	callCount int
	fail      bool
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.callCount++
	if f.fail {
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("boom"))}, nil
	}
	raw := req.URL.Query().Get("cve")
	asked := strings.Split(raw, ",")
	f.callCVEs = append(f.callCVEs, asked)
	var rows []epssRow
	for _, cve := range asked {
		if s, ok := f.scores[strings.ToUpper(cve)]; ok {
			rows = append(rows, epssRow{
				CVE:        cve,
				EPSS:       formatFloat(s.EPSS),
				Percentile: formatFloat(s.Percentile),
				Date:       s.Date,
			})
		}
	}
	body, _ := json.Marshal(epssResp{Status: "OK", Total: len(rows), Data: rows})
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
}

func formatFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func newTestClient(d Doer, cacheDir string, offline bool) *Client {
	var cache *datasource.Cache
	if cacheDir != "" {
		cache = datasource.NewCache(cacheDir, time.Hour)
	}
	return &Client{HTTP: d, Cache: cache, Endpoint: "https://example/epss", Offline: offline, Now: time.Now}
}

func TestScoresParsesAndReportsGaps(t *testing.T) {
	d := &fakeDoer{scores: map[string]Score{
		"CVE-2021-44228": {EPSS: 0.99999, Percentile: 1.0, Date: "2026-08-01"},
	}}
	c := newTestClient(d, "", false)
	// mix in a GHSA (must be ignored) and an unknown CVE (must be a gap).
	got, err := c.Scores(context.Background(), []string{"CVE-2021-44228", "GHSA-xxxx-yyyy-zzzz", "CVE-2000-0001"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got["CVE-2021-44228"].EPSS != 0.99999 {
		t.Fatalf("want one score for Log4Shell, got %v", got)
	}
	if c.Stats.Queried != 2 { // GHSA filtered out before querying
		t.Errorf("Queried = %d, want 2 (CVEs only)", c.Stats.Queried)
	}
	if c.Stats.FromNet != 1 || c.Stats.Gaps != 1 {
		t.Errorf("FromNet=%d Gaps=%d, want 1 and 1", c.Stats.FromNet, c.Stats.Gaps)
	}
}

func TestScoresBatchesByHundred(t *testing.T) {
	scores := map[string]Score{}
	var cves []string
	for i := 0; i < 250; i++ {
		cve := "CVE-2020-" + pad(i)
		cves = append(cves, cve)
		scores[cve] = Score{EPSS: 0.1, Percentile: 0.5, Date: "2026-08-01"}
	}
	d := &fakeDoer{scores: scores}
	c := newTestClient(d, "", false)
	got, err := c.Scores(context.Background(), cves)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 250 {
		t.Errorf("got %d scores, want 250", len(got))
	}
	if d.callCount != 3 { // 100 + 100 + 50
		t.Errorf("callCount = %d, want 3 (batched by 100)", d.callCount)
	}
	for _, batch := range d.callCVEs {
		if len(batch) > maxBatch {
			t.Errorf("a batch had %d CVEs, exceeds maxBatch %d", len(batch), maxBatch)
		}
	}
}

func TestScoresUsesCacheAndOffline(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDoer{scores: map[string]Score{
		"CVE-2021-44228": {EPSS: 0.99999, Percentile: 1.0, Date: "2026-08-01"},
	}}
	// First (online) call populates the cache.
	c1 := newTestClient(d, dir, false)
	if _, err := c1.Scores(context.Background(), []string{"CVE-2021-44228"}); err != nil {
		t.Fatal(err)
	}
	if d.callCount != 1 {
		t.Fatalf("expected one network call, got %d", d.callCount)
	}
	// Second call OFFLINE with a doer that would fail if hit: must serve from cache.
	failing := &fakeDoer{fail: true}
	c2 := newTestClient(failing, dir, true)
	got, err := c2.Scores(context.Background(), []string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("offline cache read should not error: %v", err)
	}
	if got["CVE-2021-44228"].EPSS != 0.99999 {
		t.Errorf("offline cache miss: %v", got)
	}
	if failing.callCount != 0 {
		t.Errorf("offline must not hit the network, got %d calls", failing.callCount)
	}
	if c2.Stats.FromCache != 1 {
		t.Errorf("FromCache = %d, want 1", c2.Stats.FromCache)
	}
}

func TestScoresOfflineColdCacheIsGapNotError(t *testing.T) {
	c := newTestClient(&fakeDoer{fail: true}, t.TempDir(), true)
	got, err := c.Scores(context.Background(), []string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("offline cold cache must not error: %v", err)
	}
	if len(got) != 0 || c.Stats.Gaps != 1 {
		t.Errorf("want zero scores and one gap, got %v gaps=%d", got, c.Stats.Gaps)
	}
}

func TestNormalizeCVEs(t *testing.T) {
	in := []string{"cve-2021-44228", "CVE-2021-44228", " GHSA-x ", "GO-2026-1", "CVE-2000-0001"}
	got := normalizeCVEs(in)
	want := []string{"CVE-2000-0001", "CVE-2021-44228"} // deduped, sorted, CVE-only
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("normalizeCVEs = %v, want %v", got, want)
	}
}

func TestEndpointQueryShape(t *testing.T) {
	d := &fakeDoer{scores: map[string]Score{"CVE-2021-44228": {EPSS: 1, Percentile: 1}}}
	c := newTestClient(d, "", false)
	if _, err := c.Scores(context.Background(), []string{"CVE-2021-44228"}); err != nil {
		t.Fatal(err)
	}
	// the fake recorded the raw cve param split; ensure it was comma-joinable
	if len(d.callCVEs) != 1 || d.callCVEs[0][0] != "CVE-2021-44228" {
		t.Errorf("unexpected query CVEs: %v", d.callCVEs)
	}
	_ = url.Values{}
}

func pad(i int) string {
	s := "0000" + itoa(i)
	return s[len(s)-4:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
