package cargo

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

// cratesFake answers both crates.io endpoints the walk uses, from memory:
//
//	GET /api/v1/crates/{name}/versions                  -> published versions
//	GET /api/v1/crates/{name}/{version}/dependencies    -> that release's deps
type cratesFake struct {
	versions map[string][]string // name -> versions
	deps     map[string]string   // "name@version" -> raw dependencies JSON array body
}

func (f *cratesFake) Do(req *http.Request) (*http.Response, error) {
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	// /api/v1/crates/<name>/versions  OR  /api/v1/crates/<name>/<version>/dependencies
	body, status := `{"errors":[{"detail":"Not Found"}]}`, 404
	switch {
	case len(parts) == 5 && parts[4] == "versions":
		name := parts[3]
		if vs, ok := f.versions[name]; ok {
			var items []string
			for _, v := range vs {
				items = append(items, `{"num":"`+v+`","created_at":"2020-01-01T00:00:00Z"}`)
			}
			body, status = `{"versions":[`+strings.Join(items, ",")+`]}`, 200
		}
	case len(parts) == 6 && parts[5] == "dependencies":
		key := parts[3] + "@" + parts[4]
		if d, ok := f.deps[key]; ok {
			body, status = `{"dependencies":`+d+`}`, 200
		}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func newCargoWalk(t *testing.T, f *cratesFake) *WalkSource {
	t.Helper()
	deps := registry.NewCargoDeps(datasource.NewCache(t.TempDir(), time.Hour), false)
	deps.HTTP = f
	idx := registry.NewCargo(datasource.NewCache(t.TempDir(), time.Hour), false)
	idx.HTTP = f
	return &WalkSource{Deps: deps, Index: idx}
}

func dep(crate, req, kind string, optional bool) string {
	o := "false"
	if optional {
		o = "true"
	}
	return `{"crate_id":"` + crate + `","req":"` + req + `","kind":"` + kind + `","optional":` + o + `}`
}

// One pinned crate, and the walk reads two layers down. The bare requirement
// "1.0.5" is a CARET in Cargo, so it admits 1.9.0 but not 2.0.0 — the semantics
// that separate Cargo from npm. A build-dependency is followed (it runs
// build.rs); a dev-dependency is not.
func TestCargoWalkDiscoversTransitiveDepth(t *testing.T) {
	f := &cratesFake{
		versions: map[string][]string{
			"layer1":     {"1.0.5", "1.9.0", "2.0.0"},
			"build-tool": {"0.2.3", "0.2.9", "0.3.0"},
			"leaf":       {"1.5.0"},
			"testonly":   {"9.9.9"},
		},
		deps: map[string]string{
			// bare "1.0.5" is caret; a build dep on build-tool; a dev dep that
			// must be ignored.
			"top@1.0.0": "[" + dep("layer1", "1.0.5", "normal", false) + "," +
				dep("build-tool", "^0.2.3", "build", false) + "," +
				dep("testonly", "1.0.0", "dev", false) + "]",
			"layer1@1.9.0":     "[" + dep("leaf", ">=1.0.0, <2.0.0", "normal", false) + "]",
			"build-tool@0.2.9": "[]",
			"leaf@1.5.0":       "[]",
		},
	}
	ws := newCargoWalk(t, f)

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:cargo/app", Kind: graph.KindPackage, Ecosystem: "cargo", Name: "app"})
	g.MarkRoot(root.ID)
	pin := g.AddNode(&graph.Node{ID: "pkg:cargo/top@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "cargo", Name: "top", Version: "1.0.0", Direct: true, Depth: 1})
	g.AddEdge(root.ID, pin.ID, graph.EdgeDependsOn)

	res, err := expand.NewWalker(ws).WithVersionIndex(ws).
		ExpandRoot(context.Background(), g, pin, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-28s truth=%-9s cand=%-3s constraint=%q", n.Depth, n.ID,
			n.VersionTruth(), n.Attr[graph.AttrVersionCandidates], n.Attr[graph.AttrDeclaredConstraint])
	}
	t.Logf("%+v", res)

	// bare "1.0.5" is caret: 1.9.0 admitted, 2.0.0 excluded.
	if g.Get("pkg:cargo/layer1@1.9.0") == nil {
		t.Error("layer1 not presumed to caret-highest 1.9.0")
	}
	if g.Get("pkg:cargo/layer1@2.0.0") != nil {
		t.Error("bare requirement was treated as >= rather than caret — admitted a major bump")
	}
	// build dependency followed to a real node.
	if g.Get("pkg:cargo/build-tool@0.2.9") == nil {
		t.Error("build-dependency was not followed (build.rs runs at compile time)")
	}
	// dev dependency ignored.
	if g.Get("pkg:cargo/testonly@9.9.9") != nil {
		t.Error("dev-dependency was pulled into the transitive tree")
	}
	// depth 3 through the range-bounded leaf.
	leaf := g.Get("pkg:cargo/leaf@1.5.0")
	if leaf == nil || leaf.Depth != 3 {
		t.Errorf("leaf not at depth 3: %+v", leaf)
	}
	if !leaf.Presumed() {
		t.Error("a walked crate version must not read as observed")
	}
}

// optional (feature-gated) dependencies are excluded by default.
func TestCargoOptionalExcludedByDefault(t *testing.T) {
	f := &cratesFake{
		versions: map[string][]string{"req": {"1.2.0"}, "maybe": {"1.0.0"}},
		deps: map[string]string{
			"top@1.0.0": "[" + dep("req", "^1.0.0", "normal", false) + "," +
				dep("maybe", "^1.0.0", "normal", true) + "]",
			"req@1.2.0": "[]",
		},
	}
	ws := newCargoWalk(t, f)
	g := graph.New()
	pin := g.AddNode(&graph.Node{ID: "pkg:cargo/top@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "cargo", Name: "top", Version: "1.0.0", Depth: 0})
	g.MarkRoot(pin.ID)
	if _, err := expand.NewWalker(ws).WithVersionIndex(ws).
		ExpandRoot(context.Background(), g, pin, expand.Options{}); err != nil {
		t.Fatal(err)
	}
	if g.Get("pkg:cargo/req@1.2.0") == nil {
		t.Error("required dependency not discovered")
	}
	if g.Get("pkg:cargo/maybe@1.0.0") != nil {
		t.Error("optional feature-gated dependency pulled in without IncludeOptional")
	}
}
