package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

func purlPyPI(name, version string) string {
	return purl.NewPyPI(name, version).String()
}

// pathDoer serves a canned requires_dist JSON body keyed by request path
// (e.g. "/pypi/flask/2.0.1/json"), so a single fake transport can answer
// several coordinates differently within one test — unlike fakeDoer in
// snapshot_export_test.go, which always returns the same body regardless of
// URL.
type pathDoer struct{ byPath map[string]string }

func (d *pathDoer) Do(req *http.Request) (*http.Response, error) {
	body, ok := d.byPath[req.URL.Path]
	if !ok {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func rootNodesOf(g *graph.Graph) []*graph.Node {
	var out []*graph.Node
	for _, id := range g.Roots {
		if n := g.Get(id); n != nil {
			out = append(out, n)
		}
	}
	return out
}

// requirementsFixture writes a minimal, provenance-free requirements.txt
// (no `# via` comments — the exact "pip freeze" shape the assessment's own
// methodology produced) and resolves it, returning the flat graph.
func requirementsFixture(t *testing.T, body string) *graph.Graph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	g, err := (&pypi.Adapter{}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cov := g.Coverage(); len(cov.FlatEcosystems) == 0 {
		t.Fatal("fixture must start flat, or this test proves nothing")
	}
	return g
}

// End-to-end, fully-reconstructible case: two pinned packages that mutually
// name each other in requires_dist, so every pinned entry finds a real
// parent among its peers and none is left genuinely root-level. Against a
// fake PyPI transport, the JSON report's flat_resolution_ecosystems must
// empty out completely.
func TestReconstructPyPIDepthEmptiesFlatEcosystemsWhenFullyReconstructible(t *testing.T) {
	g := requirementsFixture(t, "pkg-a==1.0.0\npkg-b==1.0.0\n")

	doer := &pathDoer{byPath: map[string]string{
		"/pypi/pkg-a/1.0.0/json": `{"info":{"requires_dist":["pkg-b==1.0.0"]}}`,
		"/pypi/pkg-b/1.0.0/json": `{"info":{"requires_dist":["pkg-a==1.0.0"]}}`,
	}}
	dir := t.TempDir()
	client := registry.NewPyPIDeps(datasource.NewCache(filepath.Join(dir, "cache"), 24*time.Hour), false)
	client.HTTP = doer

	cov := reconstructPyPIDepth(g, client, rootNodesOf(g))
	if cov.Error != "" || cov.Stats.Gaps > 0 {
		t.Fatalf("reconstructPyPIDepth degraded: error=%q gaps=%d", cov.Error, cov.Stats.Gaps)
	}

	gCov := g.Coverage()
	if len(gCov.FlatEcosystems) != 0 {
		t.Errorf("FlatEcosystems = %v, want empty after full reconstruction", gCov.FlatEcosystems)
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root == nil || root.Attr[pypi.AttrReconstruction] != "complete" {
		t.Errorf("root reconstruction = %+v, want complete", root)
	}
}

// End-to-end, partial case: a real requirements.txt (flask + its actual
// runtime deps) where flask itself is a genuine top-level ask that nothing
// else in the pinned set names — even with every fetch succeeding, flask
// stays root-level, so the root must stay flagged flat rather than reading
// as a fully resolved tree.
func TestReconstructPyPIDepthStaysFlatForGenuineTopLevelPackage(t *testing.T) {
	g, err := (&pypi.Adapter{}).Resolve("../../internal/ecosystem/pypi/testdata/pipfreeze")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	doer := &pathDoer{byPath: map[string]string{
		"/pypi/flask/2.0.1/json":        `{"info":{"requires_dist":["Werkzeug==2.0.1","Jinja2==3.0.1","click==8.0.1","itsdangerous==2.0.1"]}}`,
		"/pypi/werkzeug/2.0.1/json":     `{"info":{"requires_dist":[]}}`,
		"/pypi/jinja2/3.0.1/json":       `{"info":{"requires_dist":[]}}`,
		"/pypi/click/8.0.1/json":        `{"info":{"requires_dist":[]}}`,
		"/pypi/itsdangerous/2.0.1/json": `{"info":{"requires_dist":[]}}`,
	}}
	dir := t.TempDir()
	client := registry.NewPyPIDeps(datasource.NewCache(filepath.Join(dir, "cache"), 24*time.Hour), false)
	client.HTTP = doer

	cov := reconstructPyPIDepth(g, client, rootNodesOf(g))
	if cov.Error != "" || cov.Stats.Gaps > 0 {
		t.Fatalf("reconstructPyPIDepth degraded: error=%q gaps=%d", cov.Error, cov.Stats.Gaps)
	}

	gCov := g.Coverage()
	var found bool
	for _, eco := range gCov.FlatEcosystems {
		if eco == "pypi" {
			found = true
		}
	}
	if !found {
		t.Errorf("FlatEcosystems = %v, want to still include \"pypi\" after a partial reconstruction", gCov.FlatEcosystems)
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Get(id)
	}
	if root == nil || root.Attr[pypi.AttrReconstruction] != "partial" {
		t.Errorf("root reconstruction = %+v, want partial", root)
	}
	// Real edges DID form for flask's actual dependencies even though the
	// root as a whole stays flagged flat — a partial result must still carry
	// whatever structure it genuinely recovered.
	werkzeug := g.Get(purlPyPI("werkzeug", "2.0.1"))
	if werkzeug == nil || werkzeug.Direct {
		t.Errorf("werkzeug should have a real parent (flask), not stay a direct root dependency: %+v", werkzeug)
	}
	flask := g.Get(purlPyPI("flask", "2.0.1"))
	if flask == nil || !flask.Direct {
		t.Errorf("flask is genuinely root-level and should remain a direct dependency: %+v", flask)
	}
}

// -no-registry must never leave a flat PyPI root silently un-annotated: it
// must say reconstruction was never even attempted.
func TestNoRegistryDisclosesReconstructionNotAttempted(t *testing.T) {
	dir := t.TempDir()
	code := run([]string{"scan", "-format", "json", "-no-registry", "-offline",
		"-o", filepath.Join(dir, "out.json"),
		"../../internal/ecosystem/pypi/testdata/pipfreeze"})
	if code == exitUsage || code == exitInternal {
		t.Fatalf("scan exited %d, want a normal scan outcome", code)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "out.json"))
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	report := string(raw)
	if !strings.Contains(report, `"pypi.reconstruction"`) || !strings.Contains(report, `"not-attempted"`) {
		t.Errorf("report does not disclose not-attempted reconstruction: %s", raw)
	}
}
