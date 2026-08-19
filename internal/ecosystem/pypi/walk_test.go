package pypi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
)

// pypiFake answers both PyPI endpoints the walk uses, from in-memory tables, so
// the whole Nth-layer walk runs in `go test ./...` with no network:
//
//	GET /pypi/{name}/{version}/json  -> requires_dist for that exact release
//	GET /pypi/{name}/json            -> the published version list
//
// It is the registry-walk companion to the on-disk install-surface fixture in
// testdata/adversarial: that one proves the tool reads a payload buried past
// the declared layer when a lockfile pins the chain; this one proves the tool
// DISCOVERS the buried layers when the input file names only the first.
type pypiFake struct {
	requires map[string][]string // "name@version" -> requires_dist lines
	versions map[string][]string // name -> published versions
}

func (f *pypiFake) Do(req *http.Request) (*http.Response, error) {
	// A concurrent fetch loop (coordfetch) calls this from several goroutines,
	// so the fake keeps NO mutable state — an unsynchronized counter here is a
	// data race the -race build catches.
	// Path shapes: /pypi/<name>/json  or  /pypi/<name>/<version>/json
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	body, status := `{"message":"Not Found"}`, 404
	switch {
	case len(parts) == 3 && parts[0] == "pypi" && parts[2] == "json":
		name := parts[1]
		if vs, ok := f.versions[name]; ok {
			files := make([]string, 0, len(vs))
			for _, v := range vs {
				files = append(files, `"`+v+`":[{"upload_time_iso_8601":"2020-01-01T00:00:00Z"}]`)
			}
			body, status = `{"releases":{`+strings.Join(files, ",")+`}}`, 200
		}
	case len(parts) == 4 && parts[0] == "pypi" && parts[3] == "json":
		key := parts[1] + "@" + parts[2]
		if reqs, ok := f.requires[key]; ok {
			quoted := make([]string, 0, len(reqs))
			for _, r := range reqs {
				quoted = append(quoted, `"`+r+`"`)
			}
			body, status = `{"info":{"requires_dist":[`+strings.Join(quoted, ",")+`]}}`, 200
		}
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

func newWalkSource(t *testing.T, f *pypiFake) *WalkSource {
	t.Helper()
	depsCache := datasource.NewCache(t.TempDir(), time.Hour)
	verCache := datasource.NewCache(t.TempDir(), time.Hour)

	deps := registry.NewPyPIDeps(depsCache, false)
	deps.HTTP = f

	index := registry.NewPyPI(verCache, false)
	index.HTTP = f

	return &WalkSource{Deps: deps, Index: index}
}

// The motivating case, end to end through the real WalkSource: one flat pin,
// and the walk reads three layers below it — presuming a real published version
// at each — while a diamond is answered with both parents' constraints in hand.
func TestWalkDiscoversTransitiveDepthFromOnePin(t *testing.T) {
	f := &pypiFake{
		requires: map[string][]string{
			"totallyinnocent@0.11.2": {"requests>=2.0", "flask-sqlalchemy>=3.0"},
			"requests@2.31.0":        {"urllib3>=1.21,<2.0", "certifi>=2017.4.17"},
			"flask-sqlalchemy@3.1.1": {"flask>=2.2", "urllib3<2.0"},
			"urllib3@1.26.18":        {},
			"certifi@2024.2.2":       {},
			"flask@3.0.2":            {},
		},
		versions: map[string][]string{
			"requests":         {"2.0.0", "2.28.1", "2.31.0"},
			"flask-sqlalchemy": {"3.0.5", "3.1.1"},
			// urllib3 2.x is published but excluded by the accumulated <2.0.
			"urllib3": {"1.26.18", "2.0.7", "2.2.1"},
			"certifi": {"2024.2.2"},
			"flask":   {"3.0.2"},
		},
	}
	ws := newWalkSource(t, f)

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/app", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "app"})
	g.MarkRoot(root.ID)
	// A single flat pin, exactly as a one-line requirements.txt resolves.
	pin := g.AddNode(&graph.Node{
		ID: "pkg:pypi/totallyinnocent@0.11.2", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "totallyinnocent", Version: "0.11.2", Direct: true, Depth: 1,
	})
	g.AddEdge(root.ID, pin.ID, graph.EdgeDependsOn)

	res, err := expand.NewWalker(ws).WithVersionIndex(ws).
		ExpandRoot(context.Background(), g, pin, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-34s truth=%-9s cand=%-3s constraint=%q", n.Depth, n.ID,
			n.VersionTruth(), n.Attr[graph.AttrVersionCandidates], n.Attr[graph.AttrDeclaredConstraint])
	}
	t.Logf("%+v", res)

	if res.DepthReached < 3 {
		t.Errorf("depth reached = %d, want >= 3", res.DepthReached)
	}

	// requests was presumed to its highest satisfying version, from real data.
	req := g.Get("pkg:pypi/requests@2.31.0")
	if req == nil {
		t.Fatal("requests not presumed at 2.31.0")
	}
	if !req.Presumed() {
		t.Error("a walked version must not read as observed")
	}

	// The diamond: urllib3 is declared by requests (>=1.21,<2.0) and by
	// flask-sqlalchemy (<2.0). Presumed once with BOTH constraints, so 2.2.1 is
	// excluded and 1.26.18 wins — presuming per-parent would have taken 2.2.1.
	u := g.Get("pkg:pypi/urllib3@1.26.18")
	if u == nil {
		t.Fatal("urllib3 not resolved to the version satisfying both parents")
	}
	if u.Attr[graph.AttrVersionCandidates] != "1" {
		t.Errorf("urllib3 candidates = %q, want 1 (both constraints applied)", u.Attr[graph.AttrVersionCandidates])
	}

	// The original pin stays a fact, not a presumption.
	if pin.VersionTruth() != graph.TruthObserved {
		t.Errorf("pinned truth = %q, want observed", pin.VersionTruth())
	}
}

// Pre-releases are not presumed unless a constraint asks for one: presuming a
// beta would descend a tree no ordinary install produces.
func TestWalkDoesNotPresumeAPrerelease(t *testing.T) {
	f := &pypiFake{
		requires: map[string][]string{
			"app@1.0.0": {"lib>=1.0"},
			"lib@1.5.0": {},
		},
		versions: map[string][]string{"lib": {"1.5.0", "2.0.0b1"}},
	}
	ws := newWalkSource(t, f)

	g := graph.New()
	pin := g.AddNode(&graph.Node{
		ID: "pkg:pypi/app@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "app", Version: "1.0.0", Depth: 0,
	})
	g.MarkRoot(pin.ID)

	if _, err := expand.NewWalker(ws).WithVersionIndex(ws).
		ExpandRoot(context.Background(), g, pin, expand.Options{}); err != nil {
		t.Fatal(err)
	}
	if g.Get("pkg:pypi/lib@1.5.0") == nil {
		t.Error("want the stable 1.5.0, not the 2.0.0b1 pre-release")
	}
	if g.Get("pkg:pypi/lib@2.0.0b1") != nil {
		t.Error("a pre-release was presumed without a constraint asking for one")
	}
}
