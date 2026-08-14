package osv

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// fakeDoer returns a canned querybatch response and records the request body.
type fakeDoer struct {
	body     string
	calls    int
	lastBody string
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		f.lastBody = string(b)
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func TestQueryBatchClassifiesAndCaches(t *testing.T) {
	// Two coords: first has a malicious (MAL-) and a CVE; second is clean.
	resp := `{"results":[
      {"vulns":[{"id":"MAL-2026-1","modified":"2026-08-04T00:00:00Z"},{"id":"CVE-2025-9","modified":"2025-01-01T00:00:00Z"}]},
      {}
    ]}`
	doer := &fakeDoer{body: resp}
	dir := t.TempDir()
	fixed := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	cache := datasource.NewCache(dir, 24*time.Hour)
	cache.Now = func() time.Time { return fixed }
	c := &Client{
		HTTP:     doer,
		Cache:    cache,
		Endpoint: "http://test.invalid",
		Now:      func() time.Time { return fixed },
	}
	coords := []datasource.Coord{
		{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "clean", Version: "2.0.0"},
	}

	got, err := c.QueryBatch(context.Background(), coords)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if len(got[0]) != 2 || len(got[1]) != 0 {
		t.Fatalf("advisory counts = %d,%d want 2,0", len(got[0]), len(got[1]))
	}
	if !got[0][0].Malicious {
		t.Errorf("MAL- advisory not classified malicious: %+v", got[0][0])
	}
	if got[0][1].Malicious {
		t.Errorf("CVE advisory wrongly classified malicious: %+v", got[0][1])
	}
	if c.Stats.Malicious != 1 || c.Stats.Advisories != 2 || c.Stats.FromNet != 2 {
		t.Errorf("stats = %+v", c.Stats)
	}
	// Ecosystem spelling mapped correctly in the request.
	if !strings.Contains(doer.lastBody, `"ecosystem":"npm"`) {
		t.Errorf("request body missing npm ecosystem: %s", doer.lastBody)
	}

	// Second pass should be served from cache (no new network call).
	got2, err := c.QueryBatch(context.Background(), coords)
	if err != nil {
		t.Fatal(err)
	}
	if doer.calls != 1 {
		t.Errorf("expected 1 network call total, got %d", doer.calls)
	}
	if len(got2[0]) != 2 || c.Stats.FromCache != 2 {
		t.Errorf("cache pass wrong: adv=%d stats=%+v", len(got2[0]), c.Stats)
	}
}

func TestOfflineUsesCacheOnly(t *testing.T) {
	dir := t.TempDir()
	cache := datasource.NewCache(dir, time.Hour)
	// Seed the cache directly.
	co := datasource.Coord{Ecosystem: "npm", Name: "seed", Version: "1.0.0"}
	_ = cache.Put(co.Key(), []datasource.Advisory{{ID: "MAL-2026-9", Malicious: true, Source: "osv"}}, time.Now())

	doer := &fakeDoer{body: `{"results":[]}`}
	c := &Client{HTTP: doer, Cache: cache, Offline: true, Endpoint: "http://test.invalid"}

	got, err := c.QueryBatch(context.Background(), []datasource.Coord{
		co,
		{Ecosystem: "npm", Name: "missing", Version: "9.9.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if doer.calls != 0 {
		t.Errorf("offline mode made %d network calls, want 0", doer.calls)
	}
	if len(got[0]) != 1 || !got[0][0].Malicious {
		t.Errorf("seeded cache entry not returned: %+v", got[0])
	}
	if len(got[1]) != 0 || c.Stats.Gaps != 1 {
		t.Errorf("offline miss should be a gap: got=%+v gaps=%d", got[1], c.Stats.Gaps)
	}
}

// fakeBundled returns a canned answer for one key and reports a miss for
// everything else, mimicking the compiled-in fallback dataset without
// depending on its (empty, in this repo) real contents.
func fakeBundled(hitKey string, adv []datasource.Advisory, generatedAt time.Time) func(string) ([]datasource.Advisory, time.Time, bool) {
	return func(key string) ([]datasource.Advisory, time.Time, bool) {
		if key == hitKey {
			return adv, generatedAt, true
		}
		return nil, time.Time{}, false
	}
}

// AV-sandbox: an offline scan with no cached entry for a coordinate must
// still get real (if not live-fresh) coverage from the compiled-in fallback
// dataset — the same reasoning that makes -osv-snapshot worth having,
// extended to data shipped with the binary itself.
func TestOfflineFallsBackToBundledDataset(t *testing.T) {
	dir := t.TempDir()
	cache := datasource.NewCache(dir, time.Hour)
	genAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	target := datasource.Coord{Ecosystem: "npm", Name: "evil-bundled", Version: "1.0.0"}
	c := &Client{
		HTTP:    &fakeDoer{},
		Cache:   cache,
		Offline: true,
		Bundled: fakeBundled(target.Key(), []datasource.Advisory{{ID: "MAL-BUNDLED-1", Malicious: true, Source: "osv"}}, genAt),
	}

	got, err := c.QueryBatch(context.Background(), []datasource.Coord{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0]) != 1 || !got[0][0].Malicious || got[0][0].ID != "MAL-BUNDLED-1" {
		t.Fatalf("bundled advisory not returned: %+v", got[0])
	}
	if c.Stats.FromBundled != 1 {
		t.Errorf("Stats.FromBundled = %d, want 1", c.Stats.FromBundled)
	}
	if c.Stats.Gaps != 0 {
		t.Errorf("a bundled hit must not count as a gap, got Gaps=%d", c.Stats.Gaps)
	}
	if c.Stats.BundledDatasetAt == nil || !c.Stats.BundledDatasetAt.Equal(genAt) {
		t.Errorf("BundledDatasetAt = %v, want %v", c.Stats.BundledDatasetAt, genAt)
	}
	// A bundled hit must NOT be written to the on-disk cache — otherwise it
	// would look like a fresh live/cache hit on the very next run.
	if _, _, ok := cache.Get(target.Key()); ok {
		t.Error("bundled-served coordinate was persisted to the on-disk cache")
	}
}

// A coordinate the compiled-in dataset doesn't cover must still fall through
// to an ordinary gap, offline or not.
func TestOfflineBundledMissIsStillAGap(t *testing.T) {
	dir := t.TempDir()
	c := &Client{
		HTTP:    &fakeDoer{},
		Cache:   datasource.NewCache(dir, time.Hour),
		Offline: true,
		Bundled: fakeBundled("npm|something-else|1.0.0", nil, time.Time{}),
	}
	got, err := c.QueryBatch(context.Background(), []datasource.Coord{
		{Ecosystem: "npm", Name: "not-in-bundle", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0]) != 0 || c.Stats.Gaps != 1 || c.Stats.FromBundled != 0 {
		t.Errorf("uncovered coordinate should be a plain gap: got=%+v stats=%+v", got[0], c.Stats)
	}
}

// A failed LIVE query (not just an offline cache miss) must also fall back
// to the bundled dataset before giving up — this is the sandbox-blocked-
// network case the whole mechanism exists for.
func TestLiveQueryFailureFallsBackToBundledDataset(t *testing.T) {
	dir := t.TempDir()
	target := datasource.Coord{Ecosystem: "pypi", Name: "evil-live-fail", Version: "2.0.0"}
	genAt := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	c := &Client{
		HTTP:     &erroringDoer{},
		Cache:    datasource.NewCache(dir, time.Hour),
		Endpoint: "http://test.invalid",
		Bundled:  fakeBundled(target.Key(), []datasource.Advisory{{ID: "MAL-LIVEFAIL-1", Malicious: true, Source: "osv"}}, genAt),
	}

	got, err := c.QueryBatch(context.Background(), []datasource.Coord{target})
	if err == nil {
		t.Fatal("expected the live query error to still be surfaced")
	}
	if len(got[0]) != 1 || got[0][0].ID != "MAL-LIVEFAIL-1" {
		t.Fatalf("bundled fallback did not cover the failed live query: %+v", got[0])
	}
	if c.Stats.FromBundled != 1 || c.Stats.Gaps != 0 {
		t.Errorf("stats = %+v, want FromBundled=1 Gaps=0", c.Stats)
	}
}

// -no-osv-bundled sets Client.Bundled to nil; the same coordinate that would
// otherwise hit the fallback must fall through to a gap instead.
func TestNilBundledDisablesFallback(t *testing.T) {
	dir := t.TempDir()
	target := datasource.Coord{Ecosystem: "npm", Name: "would-hit-bundle", Version: "1.0.0"}
	c := &Client{
		HTTP:    &fakeDoer{},
		Cache:   datasource.NewCache(dir, time.Hour),
		Offline: true,
		Bundled: nil, // simulates -no-osv-bundled
	}
	got, err := c.QueryBatch(context.Background(), []datasource.Coord{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0]) != 0 || c.Stats.Gaps != 1 || c.Stats.FromBundled != 0 {
		t.Errorf("nil Bundled should disable fallback entirely: got=%+v stats=%+v", got[0], c.Stats)
	}
}

// erroringDoer simulates a blocked/unreachable network — the exact condition
// this sandbox hits against the real api.osv.dev.
type erroringDoer struct{}

func (*erroringDoer) Do(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}
