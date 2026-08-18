package rubygems

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

// gemFake serves the two RubyGems endpoints:
//
//	GET /api/v1/versions/{name}.json                    -> version list
//	GET /api/v2/rubygems/{name}/versions/{version}.json -> that version's deps
type gemFake struct {
	versions map[string][]string // name -> versions
	deps     map[string]string   // "name@version" -> runtime deps JSON array
}

func (f *gemFake) Do(req *http.Request) (*http.Response, error) {
	p := strings.Trim(req.URL.Path, "/")
	body, status := `{"error":"not found"}`, 404
	switch {
	case strings.HasPrefix(p, "api/v1/versions/"):
		name := strings.TrimSuffix(strings.TrimPrefix(p, "api/v1/versions/"), ".json")
		if vs, ok := f.versions[name]; ok {
			var items []string
			for _, v := range vs {
				items = append(items, `{"number":"`+v+`","created_at":"2020-01-01T00:00:00Z"}`)
			}
			body, status = "["+strings.Join(items, ",")+"]", 200
		}
	case strings.HasPrefix(p, "api/v2/rubygems/"):
		// api/v2/rubygems/<name>/versions/<version>.json
		rest := strings.TrimPrefix(p, "api/v2/rubygems/")
		parts := strings.SplitN(rest, "/versions/", 2)
		if len(parts) == 2 {
			key := parts[0] + "@" + strings.TrimSuffix(parts[1], ".json")
			if d, ok := f.deps[key]; ok {
				body, status = `{"dependencies":{"runtime":`+d+`,"development":[]}}`, 200
			}
		}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func newGemWalk(t *testing.T, f *gemFake) *WalkSource {
	t.Helper()
	deps := registry.NewGemDeps(datasource.NewCache(t.TempDir(), time.Hour), false)
	deps.HTTP = f
	idx := registry.NewGem(datasource.NewCache(t.TempDir(), time.Hour), false)
	idx.HTTP = f
	return &WalkSource{Deps: deps, Index: idx}
}

func rt(name, req string) string { return `{"name":"` + name + `","requirements":"` + req + `"}` }

// A gem with a "~>" pessimistic requirement, walked two layers, and a
// development dependency that must be ignored.
func TestGemWalkPessimisticAndRuntimeOnly(t *testing.T) {
	f := &gemFake{
		versions: map[string][]string{
			"rails":        {"6.1.0", "6.1.7", "7.0.0"},
			"actationpack": {"6.1.7"},
			"rack":         {"2.2.0", "2.2.6"},
		},
		deps: map[string]string{
			// "~> 6.1" admits 6.1.x and... <7.0, so 7.0.0 excluded; highest is 6.1.7.
			"top@1.0.0":   "[" + rt("rails", "~> 6.1") + "]",
			"rails@6.1.7": "[" + rt("rack", ">= 2.2.0") + "]",
			"rack@2.2.6":  "[]",
		},
	}
	ws := newGemWalk(t, f)

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:gem/app", Kind: graph.KindPackage, Ecosystem: "gem", Name: "app"})
	g.MarkRoot(root.ID)
	pin := g.AddNode(&graph.Node{ID: "pkg:gem/top@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "gem", Name: "top", Version: "1.0.0", Direct: true, Depth: 1})
	g.AddEdge(root.ID, pin.ID, graph.EdgeDependsOn)

	res, err := expand.NewWalker(ws).ExpandRoot(context.Background(), g, pin, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-24s truth=%-9s cand=%-3s constraint=%q", n.Depth, n.ID,
			n.VersionTruth(), n.Attr[graph.AttrVersionCandidates], n.Attr[graph.AttrDeclaredConstraint])
	}
	t.Logf("%+v", res)

	if g.Get("pkg:gem/rails@6.1.7") == nil {
		t.Error("rails not presumed to highest pessimistic-satisfying 6.1.7")
	}
	if g.Get("pkg:gem/rails@7.0.0") != nil {
		t.Error("~> 6.1 wrongly admitted 7.0.0")
	}
	if g.Get("pkg:gem/rack@2.2.6") == nil {
		t.Error("runtime dep rack not followed to depth 3")
	}
	if g.Get("pkg:gem/rack@2.2.6").Depth != 3 {
		t.Errorf("rack depth = %d, want 3", g.Get("pkg:gem/rack@2.2.6").Depth)
	}
}
