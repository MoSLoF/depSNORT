package registry

// D-163: the Maven Central release-history source serving the maven-coordinate
// nodes the clojure adapter produces (D-162). search.maven.org was
// egress-blocked in the environment this landed from, so the URL and response
// shapes are pinned here against the documented solrsearch gav API.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

type mavenDoer struct {
	body    string
	status  int
	calls   int
	lastURL string
}

func (d *mavenDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	d.lastURL = req.URL.String()
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

const mavenPostgresResp = `{"response":{"numFound":3,"docs":[
  {"id":"org.postgresql:postgresql:42.7.4","g":"org.postgresql","a":"postgresql","v":"42.7.4","timestamp":1724371200000},
  {"id":"org.postgresql:postgresql:42.7.3","g":"org.postgresql","a":"postgresql","v":"42.7.3","timestamp":1713139200000},
  {"id":"org.postgresql:postgresql:42.7.2","g":"org.postgresql","a":"postgresql","v":"42.7.2","timestamp":1708300800000}
]}}`

func TestParseMavenVersions(t *testing.T) {
	h, err := parseMavenVersions("org.postgresql:postgresql", []byte(mavenPostgresResp))
	if err != nil {
		t.Fatal(err)
	}
	if h.Ecosystem != "maven" {
		t.Errorf("ecosystem = %q, want maven", h.Ecosystem)
	}
	if len(h.Releases) != 3 {
		t.Fatalf("releases = %d, want 3", len(h.Releases))
	}
	// Sorted oldest -> newest regardless of the newest-first response order.
	if h.Releases[0].Version != "42.7.2" || h.Releases[2].Version != "42.7.4" {
		t.Errorf("sort order wrong: first %q last %q", h.Releases[0].Version, h.Releases[2].Version)
	}
	// Epoch millis decode to the real publish instant, in UTC.
	want := time.UnixMilli(1724371200000).UTC()
	if !h.Releases[2].Published.Equal(want) {
		t.Errorf("published = %v, want %v", h.Releases[2].Published, want)
	}
	// Central is immutable: no release may parse as yanked, and the yank-lure
	// shape must be structurally impossible from this source.
	for _, r := range h.Releases {
		if r.Yanked {
			t.Errorf("version %s parsed as yanked; Central cannot yank", r.Version)
		}
	}
	if _, _, ok := h.YankLureShape(); ok {
		t.Error("yank-lure shape reported from an immutable registry")
	}
	// No per-version publisher identity exists here, so VC-011's honesty
	// predicate must decline to evaluate rather than claim continuity.
	if h.PriorPublishers("42.7.4").Evaluable() {
		t.Error("publisher history must be non-evaluable: Central exposes none")
	}
}

func TestParseMavenSkipsUnusableDocs(t *testing.T) {
	raw := `{"response":{"numFound":4,"docs":[
	  {"v":"1.0.0","timestamp":1600000000000},
	  {"v":"","timestamp":1600000000001},
	  {"v":"0.9.0","timestamp":0},
	  {"v":"1.0.0","timestamp":1600000000002}
	]}}`
	h, err := parseMavenVersions("a:b", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	// The empty version, the zero timestamp (a fabricated epoch date would
	// corrupt the dormancy math), and the duplicate must all drop.
	if len(h.Releases) != 1 || h.Releases[0].Version != "1.0.0" {
		t.Fatalf("releases = %+v, want exactly one 1.0.0", h.Releases)
	}
}

func TestParseMavenMalformed(t *testing.T) {
	if _, err := parseMavenVersions("a:b", []byte(`{"response":`)); err == nil {
		t.Error("malformed JSON must error, not return an empty history")
	}
}

func TestSplitMavenCoordinate(t *testing.T) {
	cases := map[string][2]string{
		"org.postgresql:postgresql": {"org.postgresql", "postgresql"},
		"postgresql":                {"postgresql", "postgresql"}, // lein bare-symbol convention
		"a:":                        {"a:", "a:"},                 // degenerate: no artifact, used whole
	}
	for in, want := range cases {
		g, a := splitMavenCoordinate(in)
		if g != want[0] || a != want[1] {
			t.Errorf("splitMavenCoordinate(%q) = (%q,%q), want (%q,%q)", in, g, a, want[0], want[1])
		}
	}
}

func TestMavenHistoriesWireFormat(t *testing.T) {
	doer := &mavenDoer{body: mavenPostgresResp}
	c := NewMaven(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = doer

	got, err := c.Histories(context.Background(), []string{"org.postgresql:postgresql"})
	if err != nil {
		t.Fatalf("Histories: %v", err)
	}
	// The URL is the contract with search.maven.org: gav core, quoted g/a
	// terms, bounded rows, JSON, newest-first.
	for _, frag := range []string{
		"https://search.maven.org/solrsearch/select?q=",
		"g%3A%22org.postgresql%22+AND+a%3A%22postgresql%22",
		"core=gav", "rows=200", "wt=json", "sort=timestamp+desc",
	} {
		if !strings.Contains(doer.lastURL, frag) {
			t.Errorf("request URL missing %q: %s", frag, doer.lastURL)
		}
	}
	h := got["org.postgresql:postgresql"]
	if h == nil || len(h.Releases) != 3 {
		t.Fatalf("history did not round-trip: %+v", h)
	}
	if c.GetStats().FromNet != 1 {
		t.Errorf("stats.FromNet = %d, want 1", c.GetStats().FromNet)
	}
}

func TestMavenClojarsHostedArtifactIsAGapNotATimeline(t *testing.T) {
	// A Clojure-native artifact (Clojars-only) 404s on Central. That must be a
	// counted gap — never an invented history, and never a hard failure that
	// takes the whole batch down.
	doer := &mavenDoer{status: 404}
	c := NewMaven(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = doer

	got, err := c.Histories(context.Background(), []string{"com.taoensso:carmine"})
	if err != nil {
		t.Fatalf("a 404 must not fail the batch: %v", err)
	}
	if h := got["com.taoensso:carmine"]; h != nil {
		t.Errorf("no history may be fabricated for a missing artifact, got %+v", h)
	}
	if c.GetStats().NotFound != 1 {
		t.Errorf("stats.NotFound = %d, want 1 (disclosed coverage)", c.GetStats().NotFound)
	}
}
