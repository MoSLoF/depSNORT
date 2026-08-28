package registry

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// Assessment follow-up (finding #2): the untrusted-input parsers were the least
// tested code in the tree. These cover the gem/composer/nuget dependency parsers
// — which consume registry JSON — and the shared HTTP orchestrator Histories.

// ---- parseGemDeps ----------------------------------------------------------

func TestParseGemDeps(t *testing.T) {
	raw := `{"dependencies":{"runtime":[
		{"name":"rack","requirements":">= 2.0"},
		{"name":"","requirements":">= 1"},
		{"name":"json","requirements":"~> 2.3"}
	]}}`
	reqs, unparsed, err := parseGemDeps([]byte(raw))
	if err != nil {
		t.Fatalf("parseGemDeps: %v", err)
	}
	if unparsed != 0 {
		t.Errorf("unparsed = %d, want 0", unparsed)
	}
	// The empty-name entry is dropped.
	if len(reqs) != 2 {
		t.Fatalf("reqs = %+v, want 2 (empty name skipped)", reqs)
	}
	got := map[string]string{reqs[0].Name: reqs[0].Req, reqs[1].Name: reqs[1].Req}
	if got["rack"] != ">= 2.0" || got["json"] != "~> 2.3" {
		t.Errorf("unexpected reqs: %+v", reqs)
	}
}

func TestParseGemDepsMalformedErrors(t *testing.T) {
	for _, raw := range []string{"{not json", "", "[1,2,3]"} {
		if _, _, err := parseGemDeps([]byte(raw)); err == nil && raw != "" {
			t.Errorf("malformed gem JSON %q must error", raw)
		}
	}
}

// ---- parseComposerRequires + isPlatformPackage -----------------------------

func TestParseComposerRequires(t *testing.T) {
	raw := `{"packages":{"vendor/pkg":[
		{"version":"1.0.0","require":{"vendor/dep":"^1.0","php":">=7.4","ext-json":"*","other/lib":"~2.0"}},
		{"version":"v2.0.0","require":{"vendor/dep":"^2.0"}},
		{"version":"","require":{"x/y":"*"}}
	]}}`
	out := parseComposerRequires("vendor/pkg", []byte(raw))

	// 1.0.0: platform tokens (php, ext-json) filtered, real deps kept.
	v1 := out["1.0.0"]
	if len(v1) != 2 {
		t.Fatalf("1.0.0 deps = %+v, want 2 (php + ext-json filtered)", v1)
	}
	names := map[string]bool{v1[0].Name: true, v1[1].Name: true}
	if !names["vendor/dep"] || !names["other/lib"] {
		t.Errorf("1.0.0 deps names = %v, want vendor/dep + other/lib", names)
	}
	// The "v"-prefixed version is indexed under BOTH the bare and raw forms.
	if _, ok := out["2.0.0"]; !ok {
		t.Errorf("v-prefixed version must also be indexed bare as 2.0.0; got keys %v", keysOf(out))
	}
	if _, ok := out["v2.0.0"]; !ok {
		t.Errorf("raw v-prefixed version must also be kept; got keys %v", keysOf(out))
	}
	// The empty-version entry contributes no key.
	if _, ok := out[""]; ok {
		t.Errorf("empty version must not produce a key")
	}
}

func TestParseComposerRequiresMalformedReturnsNil(t *testing.T) {
	// Documented contract: malformed JSON yields nil, never a panic.
	for _, raw := range []string{"not json", "{", "[]"} {
		if out := parseComposerRequires("x", []byte(raw)); out != nil {
			t.Errorf("malformed composer JSON %q must yield nil, got %+v", raw, out)
		}
	}
}

func TestIsPlatformPackage(t *testing.T) {
	platform := []string{"php", "PHP", "hhvm", "ext-json", "lib-curl", "composer-runtime-api", "monolog"}
	notPlatform := []string{"vendor/pkg", "monolog/monolog", "symfony/console"}
	for _, p := range platform {
		if !isPlatformPackage(p) {
			t.Errorf("isPlatformPackage(%q) = false, want true", p)
		}
	}
	for _, p := range notPlatform {
		if isPlatformPackage(p) {
			t.Errorf("isPlatformPackage(%q) = true, want false", p)
		}
	}
}

// ---- parseNuGetDepGroups ---------------------------------------------------

func TestParseNuGetDepGroups(t *testing.T) {
	raw := `{"items":[{"items":[
		{"catalogEntry":{"version":"1.0.0","dependencyGroups":[
			{"dependencies":[{"id":"Newtonsoft.Json","range":"[12.0.0, )"},{"id":"Newtonsoft.Json","range":"dup"},{"id":"","range":"x"}]},
			{"dependencies":[{"id":"Serilog","range":"[2.0.0, )"}]}
		]}},
		{"catalogEntry":{"version":"","dependencyGroups":[]}}
	]}]}`
	out := parseNuGetDepGroups([]byte(raw))
	v := out["1.0.0"]
	// Newtonsoft.Json deduped across the duplicate + empty-id dropped, Serilog unioned.
	if len(v) != 2 {
		t.Fatalf("1.0.0 deps = %+v, want 2 (deduped, empty-id dropped)", v)
	}
	names := map[string]bool{v[0].Name: true, v[1].Name: true}
	if !names["Newtonsoft.Json"] || !names["Serilog"] {
		t.Errorf("deps = %+v, want Newtonsoft.Json + Serilog", v)
	}
	if _, ok := out[""]; ok {
		t.Errorf("empty version must not produce a key")
	}
}

func TestParseNuGetDepGroupsMalformedReturnsNil(t *testing.T) {
	if out := parseNuGetDepGroups([]byte("{bad")); out != nil {
		t.Errorf("malformed nuget JSON must yield nil, got %+v", out)
	}
}

func TestParseNuGetPagedLeafYieldsNoVersions(t *testing.T) {
	// A non-inlined (paged) registration leaf carries no catalogEntry items, so
	// it contributes no versions — an empty map, a frontier, not nil.
	out := parseNuGetDepGroups([]byte(`{"items":[{"items":[]}]}`))
	if out == nil || len(out) != 0 {
		t.Errorf("paged leaf must yield an empty (non-nil) map, got %+v", out)
	}
}

func keysOf(m map[string][]ComposerRequirement) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// ---- Client.Histories (the shared HTTP orchestrator) -----------------------

// historyDoer routes by the requested package name (last path segment) to a
// per-name status + body, and counts calls so a cache hit is provable. Histories
// fetches misses concurrently, so the call counter is mutex-guarded.
type historyDoer struct {
	resp map[string]struct {
		status int
		body   string
	}
	mu    sync.Mutex
	calls int
}

func (d *historyDoer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func (d *historyDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	seg := req.URL.Path
	if i := strings.LastIndex(seg, "/"); i >= 0 {
		seg = seg[i+1:]
	}
	r, ok := d.resp[seg]
	if !ok {
		r.status = 404
	}
	st := r.status
	if st == 0 {
		st = 200
	}
	return &http.Response{
		StatusCode: st,
		Body:       nopCloser{strings.NewReader(r.body)},
		Header:     make(http.Header),
	}, nil
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

func testSpec() Spec {
	return Spec{
		SourceName: "test-registry", Eco: "test", CacheTag: "test",
		Endpoint: "https://example.invalid",
		BuildURL: func(endpoint, name string) string { return endpoint + "/" + name },
		Parse: func(name string, raw []byte) (*datasource.ReleaseHistory, error) {
			return &datasource.ReleaseHistory{Package: name}, nil
		},
	}
}

func newTestClient(t *testing.T, doer Doer, offline bool) *Client {
	t.Helper()
	c := New(testSpec(), datasource.NewCache(t.TempDir(), time.Hour), offline)
	c.HTTP = doer
	// Real clock: the cache judges freshness against wall time, so a frozen past
	// timestamp would read every just-written entry as already stale.
	c.Now = time.Now
	return c
}

func TestHistoriesFetchesParsesAndCaches(t *testing.T) {
	doer := &historyDoer{resp: map[string]struct {
		status int
		body   string
	}{"ok": {200, `{}`}}}
	c := newTestClient(t, doer, false)

	got, err := c.Histories(context.Background(), []string{"ok"})
	if err != nil {
		t.Fatalf("Histories: %v", err)
	}
	if got["ok"] == nil {
		t.Fatalf("expected a history for ok")
	}
	if c.Stats.FromNet != 1 {
		t.Errorf("FromNet = %d, want 1", c.Stats.FromNet)
	}

	// Second call is served from cache — no new network call.
	before := doer.callCount()
	c2, _ := c.Histories(context.Background(), []string{"ok"})
	if c2["ok"] == nil {
		t.Fatalf("expected cached history for ok")
	}
	if doer.callCount() != before {
		t.Errorf("a cached name must not hit the network again (calls %d -> %d)", before, doer.callCount())
	}
	if c.Stats.FromCache != 1 {
		t.Errorf("FromCache = %d, want 1", c.Stats.FromCache)
	}
}

func TestHistories404IsNotFoundNotGap(t *testing.T) {
	doer := &historyDoer{resp: map[string]struct {
		status int
		body   string
	}{"missing": {404, ""}}}
	c := newTestClient(t, doer, false)
	got, err := c.Histories(context.Background(), []string{"missing"})
	if err != nil {
		t.Fatalf("a 404 must not surface as an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a 404 must omit the package, got %v", got)
	}
	if c.Stats.NotFound != 1 || c.Stats.Gaps != 0 {
		t.Errorf("404 must be NotFound=1 Gaps=0, got NotFound=%d Gaps=%d", c.Stats.NotFound, c.Stats.Gaps)
	}
}

func TestHistories500IsGapWithError(t *testing.T) {
	doer := &historyDoer{resp: map[string]struct {
		status int
		body   string
	}{"boom": {500, "upstream on fire"}}}
	c := newTestClient(t, doer, false)
	_, err := c.Histories(context.Background(), []string{"boom"})
	if err == nil {
		t.Errorf("a 500 must surface as an error")
	}
	if c.Stats.Gaps != 1 {
		t.Errorf("Gaps = %d, want 1", c.Stats.Gaps)
	}
}

func TestHistoriesOfflineColdCacheIsGap(t *testing.T) {
	doer := &historyDoer{resp: map[string]struct {
		status int
		body   string
	}{"x": {200, `{}`}}}
	c := newTestClient(t, doer, true) // offline
	_, err := c.Histories(context.Background(), []string{"x"})
	if err != nil {
		t.Fatalf("offline cold cache must not error: %v", err)
	}
	if c.Stats.Gaps != 1 {
		t.Errorf("offline with a cold cache must be a gap, got Gaps=%d", c.Stats.Gaps)
	}
	if doer.callCount() != 0 {
		t.Errorf("offline must make no network call, got %d", doer.callCount())
	}
}

func TestHistoriesDeterministicErrorSelection(t *testing.T) {
	// Two names both fail; the error returned is the sorted-first name's, so the
	// surfaced error is deterministic regardless of goroutine scheduling.
	doer := &historyDoer{resp: map[string]struct {
		status int
		body   string
	}{"zzz": {500, "z"}, "aaa": {503, "a"}}}
	c := newTestClient(t, doer, false)
	_, err := c.Histories(context.Background(), []string{"zzz", "aaa"})
	if err == nil {
		t.Fatalf("expected an error when every name fails")
	}
	if !strings.Contains(err.Error(), "aaa") {
		t.Errorf("expected the sorted-first name (aaa) error, got %v", err)
	}
}
