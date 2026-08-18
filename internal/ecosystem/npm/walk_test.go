package npm

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/npmreg"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
)

// npmFake serves packuments from memory: one document per package, carrying the
// per-version dependency maps and the time/version list the walk reads. It is
// the npm companion to the PyPI walk test — the whole Nth-layer walk runs
// offline in `go test ./...`.
type npmFake struct {
	// packuments[name] = raw JSON.
	packuments map[string]string
}

func (f *npmFake) Do(req *http.Request) (*http.Response, error) {
	// npmreg escapes "/" in scoped names to "%2f"; the last path segment is the
	// (possibly escaped) package name.
	path := strings.TrimPrefix(req.URL.Path, "/")
	name := strings.ReplaceAll(path, "%2f", "/")
	body, status := `{"error":"Not found"}`, 404
	if doc, ok := f.packuments[name]; ok {
		body, status = doc, 200
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func newNpmWalk(t *testing.T, f *npmFake) *WalkSource {
	t.Helper()
	c := npmreg.New(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = f
	return &WalkSource{Reg: c}
}

// packument builds a minimal packument: versions with dependency maps, and a
// time entry per version so the release list resolves.
func packument(name string, versions map[string]map[string]string, optional map[string]map[string]string) string {
	var vs, times []string
	for ver, deps := range versions {
		var d []string
		for n, r := range deps {
			d = append(d, `"`+n+`":"`+r+`"`)
		}
		var o []string
		for n, r := range optional[ver] {
			o = append(o, `"`+n+`":"`+r+`"`)
		}
		vs = append(vs, `"`+ver+`":{"dependencies":{`+strings.Join(d, ",")+`},"optionalDependencies":{`+strings.Join(o, ",")+`}}`)
		times = append(times, `"`+ver+`":"2020-01-01T00:00:00.000Z"`)
	}
	return `{"name":"` + name + `","time":{` + strings.Join(times, ",") + `},"versions":{` + strings.Join(vs, ",") + `}}`
}

// One pinned dependency, and the walk reads two layers below it: presuming a
// real published version through a caret range, and excluding a major bump the
// caret forbids.
func TestNpmWalkDiscoversTransitiveDepth(t *testing.T) {
	f := &npmFake{packuments: map[string]string{
		"top": packument("top", map[string]map[string]string{
			"1.0.0": {"lodash": "^4.17.0", "@acme/util": "~2.0.0"},
		}, nil),
		"lodash": packument("lodash", map[string]map[string]string{
			"4.17.21": {"nested-dep": ">=1.0.0 <2.0.0"},
		}, nil),
		"@acme/util": packument("@acme/util", map[string]map[string]string{
			"2.0.5": {},
		}, nil),
		"nested-dep": packument("nested-dep", map[string]map[string]string{
			"1.5.0": {},
		}, nil),
	}}
	// Version lists: lodash 5.x exists but ^4.17.0 must not reach it.
	f.packuments["lodash"] = packument("lodash", map[string]map[string]string{
		"4.17.0":  {"nested-dep": ">=1.0.0 <2.0.0"},
		"4.17.21": {"nested-dep": ">=1.0.0 <2.0.0"},
		"5.0.0":   {"nested-dep": ">=1.0.0 <2.0.0"},
	}, nil)
	f.packuments["@acme/util"] = packument("@acme/util", map[string]map[string]string{
		"2.0.5": {}, "2.1.0": {},
	}, nil)
	f.packuments["nested-dep"] = packument("nested-dep", map[string]map[string]string{
		"1.5.0": {}, "1.9.9": {}, "2.0.0": {},
	}, nil)

	ws := newNpmWalk(t, f)

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:npm/app", Kind: graph.KindPackage, Ecosystem: "npm", Name: "app"})
	g.MarkRoot(root.ID)
	pin := g.AddNode(&graph.Node{ID: "pkg:npm/top@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "npm", Name: "top", Version: "1.0.0", Direct: true, Depth: 1})
	g.AddEdge(root.ID, pin.ID, graph.EdgeDependsOn)

	res, err := expand.NewWalker(ws).WithVersionIndex(ws).
		ExpandRoot(context.Background(), g, pin, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-30s truth=%-9s cand=%-3s constraint=%q", n.Depth, n.ID,
			n.VersionTruth(), n.Attr[graph.AttrVersionCandidates], n.Attr[graph.AttrDeclaredConstraint])
	}
	t.Logf("%+v", res)

	// lodash: ^4.17.0 admits 4.17.0 and 4.17.21, not 5.0.0. Highest is 4.17.21.
	if g.Get("pkg:npm/lodash@4.17.21") == nil {
		t.Error("lodash not presumed to highest caret-satisfying version")
	}
	if g.Get("pkg:npm/lodash@5.0.0") != nil {
		t.Error("caret range wrongly admitted a major bump")
	}
	// The scoped dep keeps its namespace in the PURL.
	if g.Get("pkg:npm/%40acme/util@2.0.5") == nil {
		t.Error("scoped dependency lost its namespace or wrong version")
	}
	// Depth 3 reached through the range-bounded nested dep.
	nd := g.Get("pkg:npm/nested-dep@1.9.9")
	if nd == nil || nd.Depth != 3 {
		t.Errorf("nested-dep not resolved at depth 3: %+v", nd)
	}
	if !nd.Presumed() {
		t.Error("a walked version must not read as observed")
	}
	if pin.VersionTruth() != graph.TruthObserved {
		t.Error("the pinned node must stay observed")
	}
}

// optionalDependencies are MIGHT-install edges: excluded by default, present
// with -expand's IncludeOptional.
func TestNpmOptionalDependenciesExcludedByDefault(t *testing.T) {
	f := &npmFake{packuments: map[string]string{
		"top": packument("top",
			map[string]map[string]string{"1.0.0": {"req": "^1.0.0"}},
			map[string]map[string]string{"1.0.0": {"maybe": "^1.0.0"}}),
		"req":   packument("req", map[string]map[string]string{"1.2.0": {}}, nil),
		"maybe": packument("maybe", map[string]map[string]string{"1.0.0": {}}, nil),
	}}
	ws := newNpmWalk(t, f)
	g := graph.New()
	pin := g.AddNode(&graph.Node{ID: "pkg:npm/top@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "npm", Name: "top", Version: "1.0.0", Depth: 0})
	g.MarkRoot(pin.ID)

	if _, err := expand.NewWalker(ws).WithVersionIndex(ws).
		ExpandRoot(context.Background(), g, pin, expand.Options{}); err != nil {
		t.Fatal(err)
	}
	if g.Get("pkg:npm/req@1.2.0") == nil {
		t.Error("required dependency not discovered")
	}
	if g.Get("pkg:npm/maybe@1.0.0") != nil {
		t.Error("optionalDependency pulled in without IncludeOptional")
	}
}
