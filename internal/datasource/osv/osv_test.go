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
