package npmreg

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

type fakeDoer struct {
	body    string
	calls   int
	lastURL string
	status  int
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	f.lastURL = req.URL.String()
	st := f.status
	if st == 0 {
		st = 200
	}
	return &http.Response{
		StatusCode: st,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

const samplePackument = `{
  "name": "burst-pkg",
  "time": {
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2026-08-04T12:00:00.000Z",
    "1.0.0": "2020-01-01T00:00:00.000Z",
    "1.0.1": "2020-06-01T00:00:00.000Z",
    "1.0.2": "2021-01-01T00:00:00.000Z",
    "1.0.3": "2026-08-04T09:00:00.000Z",
    "1.0.4": "2026-08-04T10:00:00.000Z",
    "1.0.5": "2026-08-04T11:00:00.000Z"
  },
  "maintainers": [{"name":"someone","email":"a@b.c"}]
}`

func TestHistoriesParsesAndCaches(t *testing.T) {
	doer := &fakeDoer{body: samplePackument}
	dir := t.TempDir()
	fixed := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	cache := datasource.NewCache(dir, time.Hour)
	// Pin the cache clock too, so freshness is deterministic rather than a race
	// against the wall clock.
	cache.Now = func() time.Time { return fixed }
	c := &Client{
		HTTP: doer, Cache: cache,
		Endpoint: "http://test.invalid", Now: func() time.Time { return fixed },
	}

	got, err := c.Histories(context.Background(), []string{"burst-pkg"})
	if err != nil {
		t.Fatalf("Histories: %v", err)
	}
	h := got["burst-pkg"]
	if h == nil {
		t.Fatal("no history returned")
	}
	if len(h.Releases) != 6 {
		t.Fatalf("releases = %d, want 6 (created/modified must be excluded)", len(h.Releases))
	}
	// Sorted oldest first.
	if h.Releases[0].Version != "1.0.0" || h.Releases[5].Version != "1.0.5" {
		t.Errorf("releases not sorted: %s .. %s", h.Releases[0].Version, h.Releases[5].Version)
	}
	if len(h.Maintainers) != 1 || h.Maintainers[0] != "someone" {
		t.Errorf("maintainers = %v", h.Maintainers)
	}

	// Second call must hit the cache.
	if _, err := c.Histories(context.Background(), []string{"burst-pkg"}); err != nil {
		t.Fatal(err)
	}
	if doer.calls != 1 {
		t.Errorf("network calls = %d, want 1", doer.calls)
	}
	if c.Stats.FromCache != 1 {
		t.Errorf("stats = %+v", c.Stats)
	}
}

func TestOfflineColdCacheIsGapNotError(t *testing.T) {
	doer := &fakeDoer{body: samplePackument}
	c := &Client{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour), Offline: true}
	got, err := c.Histories(context.Background(), []string{"burst-pkg"})
	if err != nil {
		t.Fatalf("offline cold cache should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no histories, got %d", len(got))
	}
	if doer.calls != 0 {
		t.Errorf("offline made %d network calls", doer.calls)
	}
	if c.Stats.Gaps != 1 {
		t.Errorf("gaps = %d, want 1", c.Stats.Gaps)
	}
}

func TestScopedNameEscaping(t *testing.T) {
	doer := &fakeDoer{body: `{"name":"@scope/pkg","time":{}}`}
	c := &Client{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour), Endpoint: "http://test.invalid"}
	if _, err := c.Histories(context.Background(), []string{"@scope/pkg"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doer.lastURL, "%2F") {
		t.Errorf("scoped name not escaped: %s", doer.lastURL)
	}
}

// (A former TestHTTPErrorIsGap asserted that a 404 produced an error and a
// coverage gap. That behaviour was wrong: a package absent from the public
// registry is an ordinary fact, not a failed lookup. It is superseded by
// TestNotFoundIsNotAnError and TestServerErrorStillDegrades below.)

func TestMedianIntervalAndDecay(t *testing.T) {
	h := &datasource.ReleaseHistory{Releases: []datasource.Release{
		{Version: "1", Published: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Version: "2", Published: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		{Version: "3", Published: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
		{Version: "4", Published: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)},
	}}
	if m := h.MedianInterval(); m < 27*24*time.Hour || m > 32*24*time.Hour {
		t.Errorf("median interval = %v, want ~30d", m)
	}
	// Decay: one half-life halves the weight.
	if d := datasource.Decay(datasource.DefaultHalfLife, datasource.DefaultHalfLife); d < 0.49 || d > 0.51 {
		t.Errorf("decay at one half-life = %v, want ~0.5", d)
	}
	if d := datasource.Decay(0, datasource.DefaultHalfLife); d != 1 {
		t.Errorf("decay at age 0 = %v, want 1", d)
	}
}

// A 404 means "not published on this registry" — normal for private and
// internal packages. It must be counted separately and must NOT make the scan
// look degraded by returning an error.
func TestNotFoundIsNotAnError(t *testing.T) {
	doer := &fakeDoer{body: `{"error":"Not found"}`, status: 404}
	c := &Client{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour), Endpoint: "http://test.invalid"}
	got, err := c.Histories(context.Background(), []string{"private-pkg"})
	if err != nil {
		t.Errorf("404 should not surface as an error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no history, got %d", len(got))
	}
	if c.Stats.NotFound != 1 {
		t.Errorf("NotFound = %d, want 1", c.Stats.NotFound)
	}
	if c.Stats.Gaps != 0 {
		t.Errorf("a 404 must not be counted as a coverage gap, got %d", c.Stats.Gaps)
	}
}

// A 500 IS a real failure and must still degrade coverage loudly.
func TestServerErrorStillDegrades(t *testing.T) {
	doer := &fakeDoer{body: "boom", status: 500}
	c := &Client{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour), Endpoint: "http://test.invalid"}
	if _, err := c.Histories(context.Background(), []string{"x"}); err == nil {
		t.Error("a 500 should surface as an error")
	}
	if c.Stats.Gaps != 1 || c.Stats.NotFound != 0 {
		t.Errorf("stats = %+v, want gaps=1 notfound=0", c.Stats)
	}
}

// slowDoer records peak concurrency so the test can prove fetches overlap
// rather than merely asserting the code compiles.
type slowDoer struct {
	mu    sync.Mutex
	cur   int
	peak  int
	calls int
	delay time.Duration
	body  string
}

func (d *slowDoer) Do(*http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.calls++
	d.cur++
	if d.cur > d.peak {
		d.peak = d.cur
	}
	d.mu.Unlock()

	time.Sleep(d.delay)

	d.mu.Lock()
	d.cur--
	d.mu.Unlock()
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     make(http.Header),
	}, nil
}

// A serial implementation would peak at 1 and take len(names)*delay. Bounded
// parallelism must overlap requests while never exceeding the cap.
func TestHistoriesFetchesConcurrently(t *testing.T) {
	const n = 24
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("pkg-%02d", i)
	}
	doer := &slowDoer{delay: 40 * time.Millisecond, body: `{"name":"x","time":{"1.0.0":"2026-01-01T00:00:00.000Z"}}`}
	c := &Client{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour), Endpoint: "http://test.invalid"}

	start := time.Now()
	got, err := c.Histories(context.Background(), names)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Fatalf("histories = %d, want %d", len(got), n)
	}
	if doer.calls != n {
		t.Errorf("calls = %d, want %d", doer.calls, n)
	}
	if doer.peak < 2 {
		t.Errorf("peak concurrency = %d — fetches did not overlap", doer.peak)
	}
	if doer.peak > registryConcurrency {
		t.Errorf("peak concurrency = %d exceeds the %d cap", doer.peak, registryConcurrency)
	}
	// Serial would be >= 24*40ms = 960ms; concurrent should be a fraction.
	if elapsed > 700*time.Millisecond {
		t.Errorf("elapsed %v suggests serial execution", elapsed)
	}
	t.Logf("peak concurrency %d, elapsed %v (serial would be ~%v)", doer.peak, elapsed, n*40*time.Millisecond)
}

// Every result must still be cached, regardless of completion order.
func TestConcurrentResultsAreAllCached(t *testing.T) {
	names := []string{"a-pkg", "b-pkg", "c-pkg", "d-pkg", "e-pkg"}
	dir := t.TempDir()
	doer := &slowDoer{delay: 5 * time.Millisecond, body: `{"name":"x","time":{"1.0.0":"2026-01-01T00:00:00.000Z"}}`}
	c := &Client{HTTP: doer, Cache: datasource.NewCache(dir, time.Hour), Endpoint: "http://test.invalid"}
	if _, err := c.Histories(context.Background(), names); err != nil {
		t.Fatal(err)
	}
	if c.Stats.FromNet != len(names) {
		t.Fatalf("FromNet = %d, want %d", c.Stats.FromNet, len(names))
	}
	// Second pass must be fully cache-served with zero new requests.
	before := doer.calls
	c2 := &Client{HTTP: doer, Cache: datasource.NewCache(dir, time.Hour), Endpoint: "http://test.invalid"}
	if _, err := c2.Histories(context.Background(), names); err != nil {
		t.Fatal(err)
	}
	if doer.calls != before {
		t.Errorf("second pass made %d new requests, want 0", doer.calls-before)
	}
	if c2.Stats.FromCache != len(names) {
		t.Errorf("FromCache = %d, want %d", c2.Stats.FromCache, len(names))
	}
}
