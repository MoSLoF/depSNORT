package composer

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

// composerFake serves the Packagist p2 endpoint: one document per package
// carrying every version and its `require` map.
type composerFake struct {
	packages map[string]string // "vendor/name" -> p2 JSON
}

func (f *composerFake) Do(req *http.Request) (*http.Response, error) {
	// /p2/<vendor>/<name>.json
	p := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/p2/"), ".json")
	body, status := `{"error":"not found"}`, 404
	if doc, ok := f.packages[strings.ToLower(p)]; ok {
		body, status = doc, 200
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func newComposerWalk(t *testing.T, f *composerFake) *WalkSource {
	t.Helper()
	deps := registry.NewComposerDeps(datasource.NewCache(t.TempDir(), time.Hour), false)
	deps.HTTP = f
	idx := registry.NewComposer(datasource.NewCache(t.TempDir(), time.Hour), false)
	idx.HTTP = f
	return &WalkSource{Deps: deps, Index: idx}
}

// p2doc builds a Packagist p2 document for one package: versions in descending
// order, each with a require map. The version-history parser and the deps
// parser both read this same body.
func p2doc(name string, versions []string, requires map[string]map[string]string) string {
	var vs []string
	for _, v := range versions {
		var reqs []string
		for dep, c := range requires[v] {
			reqs = append(reqs, `"`+dep+`":"`+c+`"`)
		}
		vs = append(vs, `{"version":"`+v+`","time":"2020-01-01T00:00:00+00:00","require":{`+strings.Join(reqs, ",")+`}}`)
	}
	return `{"packages":{"` + name + `":[` + strings.Join(vs, ",") + `]}}`
}

// A Composer package with a pessimistic "~" (distinct from npm) and a platform
// requirement that must be ignored, walked two layers.
func TestComposerWalkTildeAndPlatformFilter(t *testing.T) {
	f := &composerFake{packages: map[string]string{
		"acme/top": p2doc("acme/top", []string{"1.0.0"}, map[string]map[string]string{
			"1.0.0": {"php": ">=7.4", "monolog/monolog": "~2.3", "ext-json": "*"},
		}),
		"monolog/monolog": p2doc("monolog/monolog", []string{"2.9.0", "2.3.0", "3.0.0"}, map[string]map[string]string{
			"2.9.0": {"psr/log": "^1.1"},
		}),
		"psr/log": p2doc("psr/log", []string{"1.1.4"}, nil),
	}}
	ws := newComposerWalk(t, f)

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:composer/app", Kind: graph.KindPackage, Ecosystem: "composer", Name: "app"})
	g.MarkRoot(root.ID)
	pin := g.AddNode(&graph.Node{ID: "pkg:composer/acme/top@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "composer", Name: "acme/top", Version: "1.0.0", Direct: true, Depth: 1})
	g.AddEdge(root.ID, pin.ID, graph.EdgeDependsOn)

	res, err := expand.NewWalker(ws).ExpandRoot(context.Background(), g, pin, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-34s truth=%-9s cand=%-3s constraint=%q", n.Depth, n.ID,
			n.VersionTruth(), n.Attr[graph.AttrVersionCandidates], n.Attr[graph.AttrDeclaredConstraint])
	}
	t.Logf("%+v", res)

	// "~2.3" is pessimistic: >=2.3.0 <3.0.0, so 2.9.0 admitted, 3.0.0 excluded.
	if g.Get("pkg:composer/monolog/monolog@2.9.0") == nil {
		t.Error("monolog not presumed to pessimistic-highest 2.9.0")
	}
	if g.Get("pkg:composer/monolog/monolog@3.0.0") != nil {
		t.Error("~2.3 wrongly admitted 3.0.0 (npm tilde would too — this proves pessimistic)")
	}
	// platform requirements dropped.
	if g.Get("pkg:composer/php") != nil || g.Get("pkg:composer/ext-json") != nil {
		t.Error("a platform requirement was walked as a package")
	}
	// depth 3.
	psr := g.Get("pkg:composer/psr/log@1.1.4")
	if psr == nil || psr.Depth != 3 {
		t.Errorf("psr/log not at depth 3: %+v", psr)
	}
}
