package gomod

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/goproxy"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// goProxyFake answers the two proxy endpoints from memory.
type goProxyFake struct {
	versions map[string][]string // module -> versions
	mods     map[string]string   // "module@version" -> go.mod text
}

func (f *goProxyFake) Do(req *http.Request) (*http.Response, error) {
	p := req.URL.Path
	body, status := "not found", 404
	// /{module}/@v/list  or  /{module}/@v/{version}.mod  (module may be !-escaped)
	if strings.HasSuffix(p, "/@v/list") {
		mod := unescape(strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/@v/list"))
		if vs, ok := f.versions[mod]; ok {
			body, status = strings.Join(vs, "\n"), 200
		}
	} else if strings.HasSuffix(p, ".mod") {
		i := strings.Index(p, "/@v/")
		mod := unescape(strings.TrimPrefix(p[:i], "/"))
		ver := strings.TrimSuffix(p[i+4:], ".mod")
		if m, ok := f.mods[mod+"@"+ver]; ok {
			body, status = m, 200
		}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '!' && i+1 < len(s) {
			b.WriteByte(s[i+1] - ('a' - 'A'))
			i++
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func newGoWalk(t *testing.T, f *goProxyFake) *WalkSource {
	t.Helper()
	c := goproxy.New(datasource.NewCache(t.TempDir(), time.Hour), false)
	c.HTTP = f
	return &WalkSource{Proxy: c}
}

// One pinned module, and the walk reads its transitive tree from the proxy,
// presuming the LOWEST version satisfying the accumulated minimums (Go MVS).
func TestGoWalkReconstructsAndPresumesLowest(t *testing.T) {
	f := &goProxyFake{
		versions: map[string][]string{
			"github.com/foo/lib":  {"v1.0.0", "v1.2.0", "v1.5.0"},
			"github.com/bar/util": {"v0.1.0", "v0.3.0"},
		},
		mods: map[string]string{
			"github.com/app/top@v1.0.0": "module github.com/app/top\ngo 1.21\nrequire (\n github.com/foo/lib v1.2.0\n)\n",
			// lib requires util at a minimum; walk should presume the lowest >=.
			"github.com/foo/lib@v1.2.0":  "module github.com/foo/lib\ngo 1.21\nrequire github.com/bar/util v0.1.0\n",
			"github.com/bar/util@v0.1.0": "module github.com/bar/util\ngo 1.21\n",
		},
	}
	ws := newGoWalk(t, f)

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "root", Kind: graph.KindPackage, Ecosystem: "gomod", Name: "root"})
	g.MarkRoot(root.ID)
	pin := g.AddNode(&graph.Node{ID: purl.NewGo("github.com/app/top", "v1.0.0").String(),
		Kind: graph.KindPackage, Ecosystem: "gomod", Name: "github.com/app/top", Version: "v1.0.0", Depth: 1})
	pin.SetSource(graph.SourceRegistry, "")
	g.AddEdge(root.ID, pin.ID, graph.EdgeDependsOn)

	res, err := expand.NewWalker(ws).ExpandRoot(context.Background(), g, pin, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-42s truth=%s cand=%s", n.Depth, n.ID, n.VersionTruth(), n.Attr[graph.AttrVersionCandidates])
	}
	t.Logf("%+v", res)

	// foo/lib required >=v1.2.0; lowest satisfying published is v1.2.0 (not v1.5.0).
	lib := g.Get(purl.NewGo("github.com/foo/lib", "v1.2.0").String())
	if lib == nil {
		t.Fatal("foo/lib not presumed to the lowest satisfying v1.2.0")
	}
	if g.Get(purl.NewGo("github.com/foo/lib", "v1.5.0").String()) != nil {
		t.Error("Go walk presumed the newest version, but MVS takes the lowest satisfying")
	}
	// util required >=v0.1.0; lowest published satisfying is v0.1.0.
	if g.Get(purl.NewGo("github.com/bar/util", "v0.1.0").String()) == nil {
		t.Error("transitive util not reconstructed at depth 3")
	}
}
