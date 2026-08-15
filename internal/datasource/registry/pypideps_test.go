package registry

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

type pypiDepsDoer struct {
	body   string
	status int
	calls  int
}

func (d *pypiDepsDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	st := d.status
	if st == 0 {
		st = 200
	}
	return &http.Response{
		StatusCode: st,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     make(http.Header),
	}, nil
}

func TestParseRequiresDistFiltersExtrasAndNormalizes(t *testing.T) {
	raw := `{"info":{"requires_dist":[
		"Flask_SQLAlchemy==2.5.1",
		"urllib3>=1.21.1",
		"aiohttp ; extra == \"async\"",
		"pywin32 ; sys_platform == \"win32\" and extra == \"windows\""
	]}}`
	names, unparsed, err := parseRequiresDist([]byte(raw))
	if err != nil {
		t.Fatalf("parseRequiresDist: %v", err)
	}
	if unparsed != 0 {
		t.Errorf("unparsed = %d, want 0 (every entry here is well-formed)", unparsed)
	}
	want := map[string]bool{"flask-sqlalchemy": true, "urllib3": true}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want exactly %v (extras-gated entries dropped)", names, want)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected name %q in %v", n, names)
		}
	}
}

func TestParseRequiresDistBadJSON(t *testing.T) {
	if _, _, err := parseRequiresDist([]byte("not json")); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestRequiresDistFetchesParsesAndCaches(t *testing.T) {
	doer := &pypiDepsDoer{body: `{"info":{"requires_dist":["click==8.0.1","itsdangerous>=2.0"]}}`}
	dir := t.TempDir()
	cache := datasource.NewCache(dir, time.Hour)
	c := &PyPIDepsClient{HTTP: doer, Cache: cache, Now: time.Now}
	coord := datasource.Coord{Ecosystem: "pypi", Name: "flask", Version: "2.0.1"}

	got, err := c.RequiresDist(context.Background(), []datasource.Coord{coord})
	if err != nil {
		t.Fatalf("RequiresDist: %v", err)
	}
	names := got[coord.Key()]
	if len(names) != 2 || names[0] != "click" || names[1] != "itsdangerous" {
		t.Fatalf("names = %v, want [click itsdangerous]", names)
	}
	if c.Stats.FromNet != 1 {
		t.Errorf("Stats.FromNet = %d, want 1", c.Stats.FromNet)
	}

	// Second call must be served entirely from cache.
	if _, err := c.RequiresDist(context.Background(), []datasource.Coord{coord}); err != nil {
		t.Fatal(err)
	}
	if doer.calls != 1 {
		t.Errorf("network calls = %d, want 1 (second lookup should hit cache)", doer.calls)
	}
	if c.Stats.FromCache != 1 {
		t.Errorf("Stats.FromCache = %d, want 1", c.Stats.FromCache)
	}
}

func TestRequiresDistOfflineColdCacheIsGapNotError(t *testing.T) {
	doer := &pypiDepsDoer{body: `{"info":{"requires_dist":["click==8.0.1"]}}`}
	c := &PyPIDepsClient{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour), Offline: true}
	coord := datasource.Coord{Ecosystem: "pypi", Name: "flask", Version: "2.0.1"}

	got, err := c.RequiresDist(context.Background(), []datasource.Coord{coord})
	if err != nil {
		t.Fatalf("offline cold cache should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no entries, got %d", len(got))
	}
	if doer.calls != 0 {
		t.Errorf("offline made %d network calls, want 0", doer.calls)
	}
	if c.Stats.Gaps != 1 {
		t.Errorf("Stats.Gaps = %d, want 1", c.Stats.Gaps)
	}
}

func TestRequiresDistNotFoundIsNotAnError(t *testing.T) {
	doer := &pypiDepsDoer{body: `{"message":"Not Found"}`, status: 404}
	c := &PyPIDepsClient{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour)}
	coord := datasource.Coord{Ecosystem: "pypi", Name: "private-pkg", Version: "1.0.0"}

	got, err := c.RequiresDist(context.Background(), []datasource.Coord{coord})
	if err != nil {
		t.Errorf("404 should not surface as an error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no entries, got %d", len(got))
	}
	if c.Stats.NotFound != 1 {
		t.Errorf("Stats.NotFound = %d, want 1", c.Stats.NotFound)
	}
	if c.Stats.Gaps != 0 {
		t.Errorf("a 404 must not count as a gap, got %d", c.Stats.Gaps)
	}
}

func TestRequiresDistServerErrorDegrades(t *testing.T) {
	doer := &pypiDepsDoer{body: "boom", status: 500}
	c := &PyPIDepsClient{HTTP: doer, Cache: datasource.NewCache(t.TempDir(), time.Hour)}
	coord := datasource.Coord{Ecosystem: "pypi", Name: "flask", Version: "2.0.1"}

	if _, err := c.RequiresDist(context.Background(), []datasource.Coord{coord}); err == nil {
		t.Error("a 500 should surface as an error")
	}
	if c.Stats.Gaps != 1 || c.Stats.NotFound != 0 {
		t.Errorf("stats = %+v, want gaps=1 notfound=0", c.Stats)
	}
}

// TestParseRequiresDistRealRequestsCompoundSpecifiers is the regression test for
// the reported finding (HoneyBadger Vanguard, iHBV-TM-022). These four entries
// are verbatim from requests' published PyPI requires_dist metadata. Three of
// them are comma-joined compound specifiers, which the previous operator-scanning
// parser corrupted into "charset-normalizer<4,", "idna<4," and "urllib3<3," —
// names that then failed to match their real graph nodes, so genuine transitive
// dependencies were stamped pypi.parent_status "root-level" (depSNORT's own
// "confidently a direct dependency" claim) with nothing disclosed.
func TestParseRequiresDistRealRequestsCompoundSpecifiers(t *testing.T) {
	raw := `{"info":{"requires_dist":[
		"charset_normalizer<4,>=2",
		"idna<4,>=2.5",
		"urllib3<3,>=1.26",
		"certifi>=2017.4.17"
	]}}`
	names, unparsed, err := parseRequiresDist([]byte(raw))
	if err != nil {
		t.Fatalf("parseRequiresDist: %v", err)
	}
	if unparsed != 0 {
		t.Errorf("unparsed = %d, want 0", unparsed)
	}
	want := []string{"charset-normalizer", "idna", "urllib3", "certifi"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("names[%d] = %q, want %q", i, names[i], w)
		}
	}
}

// TestParseRequiresDistCountsUnparsedSeparatelyFromExtras locks the D-24
// distinction: an extras-gated entry is a deliberate documented exclusion, an
// unparseable one is a missing edge. They were previously conflated in a single
// skip, hiding the second behind the first.
func TestParseRequiresDistCountsUnparsedSeparatelyFromExtras(t *testing.T) {
	raw := `{"info":{"requires_dist":[
		"click>=8",
		"aiohttp ; extra == \"async\"",
		"https://example.invalid/x/foo-1.0.tar.gz",
		"-not-a-name"
	]}}`
	names, unparsed, err := parseRequiresDist([]byte(raw))
	if err != nil {
		t.Fatalf("parseRequiresDist: %v", err)
	}
	if len(names) != 1 || names[0] != "click" {
		t.Errorf("names = %v, want [click]", names)
	}
	if unparsed != 2 {
		t.Errorf("unparsed = %d, want 2 (the URL and the invalid name; the extras-gated entry is NOT unparsed)", unparsed)
	}
}
