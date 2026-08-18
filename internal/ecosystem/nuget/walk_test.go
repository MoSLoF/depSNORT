package nuget

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

// nugetFake serves the registration index for each package. The one document
// carries both the version list AND the per-version dependencyGroups, so both
// walk reads hit it.
type nugetFake struct {
	// indexes[lowerName] = raw registration index JSON
	indexes map[string]string
}

func (f *nugetFake) Do(req *http.Request) (*http.Response, error) {
	// .../registration5-gz-semver2/<id-lower>/index.json
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	body, status := `{"error":"not found"}`, 404
	if len(parts) >= 2 {
		name := parts[len(parts)-2]
		if doc, ok := f.indexes[strings.ToLower(name)]; ok {
			body, status = doc, 200
		}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func newNuGetWalk(t *testing.T, f *nugetFake) *WalkSource {
	t.Helper()
	deps := registry.NewNuGetDeps(datasource.NewCache(t.TempDir(), time.Hour), false)
	deps.HTTP = f
	idx := registry.NewNuGet(datasource.NewCache(t.TempDir(), time.Hour), false)
	idx.HTTP = f
	return &WalkSource{Deps: deps, Index: idx}
}

// leaf builds one registration leaf: a version, its publish time, and its
// dependency ranges.
func leaf(version string, deps map[string]string) string {
	var ds []string
	for _, id := range sortedKeys(deps) {
		ds = append(ds, `{"id":"`+id+`","range":"`+deps[id]+`"}`)
	}
	depGroups := ""
	if len(ds) > 0 {
		depGroups = `,"dependencyGroups":[{"dependencies":[` + strings.Join(ds, ",") + `]}]`
	}
	return `{"catalogEntry":{"version":"` + version + `","published":"2020-01-01T00:00:00Z","listed":true` + depGroups + `}}`
}

func sortedKeys(m map[string]string) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	// tiny insertion sort to avoid an import
	for i := 1; i < len(k); i++ {
		for j := i; j > 0 && k[j-1] > k[j]; j-- {
			k[j-1], k[j] = k[j], k[j-1]
		}
	}
	return k
}

func index(leaves ...string) string {
	return `{"items":[{"items":[` + strings.Join(leaves, ",") + `]}]}`
}

// One pin, and the walk descends two layers — presuming the LOWEST satisfying
// version at each, which is NuGet's resolution, not the highest. Interval and
// bare-minimum ranges are both exercised.
func TestNuGetWalkPresumesLowestSatisfying(t *testing.T) {
	f := &nugetFake{indexes: map[string]string{
		"top": index(leaf("1.0.0", map[string]string{
			"Serilog":         "[2.0.0, 3.0.0)", // interval
			"Newtonsoft.Json": "12.0.1",         // bare = minimum
		})),
		"serilog": index(
			leaf("2.0.0", map[string]string{"span-dep": "[1.0.0, )"}),
			leaf("2.5.0", nil),
			leaf("3.0.0", nil), // excluded by the half-open upper bound
		),
		"newtonsoft.json": index(
			leaf("12.0.1", nil),
			leaf("13.0.1", nil), // higher, but NuGet takes the lowest >= 12.0.1
		),
		"span-dep": index(leaf("1.0.0", nil), leaf("1.5.0", nil)),
	}}
	ws := newNuGetWalk(t, f)

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:nuget/app", Kind: graph.KindPackage, Ecosystem: "nuget", Name: "app"})
	g.MarkRoot(root.ID)
	pin := g.AddNode(&graph.Node{ID: "pkg:nuget/top@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "nuget", Name: "top", Version: "1.0.0", Direct: true, Depth: 1})
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

	// Serilog [2.0.0,3.0.0): candidates 2.0.0 and 2.5.0; NuGet takes the LOWEST.
	if g.Get("pkg:nuget/serilog@2.0.0") == nil {
		t.Error("Serilog not presumed to the lowest satisfying 2.0.0")
	}
	if g.Get("pkg:nuget/serilog@2.5.0") != nil {
		t.Error("presumed a higher version than NuGet would install")
	}
	// Newtonsoft.Json 12.0.1 (minimum): candidates 12.0.1 and 13.0.1; lowest wins.
	if g.Get("pkg:nuget/newtonsoft.json@12.0.1") == nil {
		t.Error("Newtonsoft.Json not presumed to the lowest >= 12.0.1")
	}
	// Depth 3 through the interval-bounded transitive dep.
	sp := g.Get("pkg:nuget/span-dep@1.0.0")
	if sp == nil || sp.Depth != 3 {
		t.Errorf("span-dep not at depth 3: %+v", sp)
	}
	if !sp.Presumed() {
		t.Error("a walked version must not read as observed")
	}
}
