package osv

import (
	"context"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// D-162: a maven-coordinate node (the clojure adapter's project.clj /
// deps.edn pins) must reach OSV as ecosystem "Maven" with the group:artifact
// name intact — OSV's documented Maven spelling. Passing the internal id
// through unmapped would silently return zero advisories, which on the
// swytch.jepsen shape means three real postgresql advisories invisible again.
// The live api.osv.dev round-trip was egress-blocked in the environment this
// landed from, so the wire format is pinned here instead.
func TestMavenCoordReachesOSVAsMaven(t *testing.T) {
	resp := `{"results":[
      {"vulns":[{"id":"GHSA-hq9p-pm7w-8p54","modified":"2026-01-01T00:00:00Z"}]}
    ]}`
	doer := &fakeDoer{body: resp}
	fixed := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	cache := datasource.NewCache(t.TempDir(), 24*time.Hour)
	cache.Now = func() time.Time { return fixed }
	c := &Client{
		HTTP:     doer,
		Cache:    cache,
		Endpoint: "http://test.invalid",
		Now:      func() time.Time { return fixed },
	}

	got, err := c.QueryBatch(context.Background(), []datasource.Coord{
		{Ecosystem: "maven", Name: "org.postgresql:postgresql", Version: "42.7.4"},
	})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if !strings.Contains(doer.lastBody, `"ecosystem":"Maven"`) {
		t.Errorf("request must carry OSV's Maven spelling, got body: %s", doer.lastBody)
	}
	if !strings.Contains(doer.lastBody, `"name":"org.postgresql:postgresql"`) {
		t.Errorf("request must carry the group:artifact coordinate verbatim, got body: %s", doer.lastBody)
	}
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].ID != "GHSA-hq9p-pm7w-8p54" {
		t.Errorf("advisory must round-trip onto the maven coord, got %+v", got)
	}
}
