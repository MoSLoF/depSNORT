package npm

import (
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// D-148: a dependency whose directory was absent (a pre-install tree) was
// silently skipped — treated as the "normal absence" half of R-01, when the
// absent thing was the dependency's entire source. The lockfile's
// hasInstallScript flag (VC-002a) still stood, but that flag is the registry's
// assertion; the hook CONTENT the cradle checks read, and the entry module's
// load-time chain, were unexamined and undisclosed.

func d148NpmTree(t *testing.T, installed bool) (string, *graph.Graph) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"dep":"1.0.0"}}`)
	if installed {
		writeFile(t, dir, "node_modules/dep/package.json",
			`{"name":"dep","version":"1.0.0","scripts":{"postinstall":"node ok.js"}}`)
		writeFile(t, dir, "node_modules/dep/ok.js", "module.exports=1")
	}
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:npm/app@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "app", Version: "1.0.0", Attr: map[string]string{"npm.path": "."},
	})
	g.MarkRoot(root.ID)
	dep := g.AddNode(&graph.Node{
		ID: "pkg:npm/dep@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "dep", Version: "1.0.0", Depth: 1,
		Attr: map[string]string{"npm.path": "node_modules/dep"},
	})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)
	return dir, g
}

func TestD148PreInstallTreeDisclosesPerDependency(t *testing.T) {
	dir, g := d148NpmTree(t, false)
	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	if err == nil {
		t.Fatal("an uninstalled dependency is unexamined and must surface as a gap")
	}
	gaps := instsurf.GapsOf(err)
	if len(gaps) != 1 || gaps[0].Reason != instsurf.GapUnavailable {
		t.Fatalf("want one source-unavailable gap for the dependency, got %v", gaps)
	}
	if gaps[0].Package != "pkg:npm/dep@1.0.0" {
		t.Errorf("the gap must name the dependency, got %q", gaps[0].Package)
	}
}

// TestD148InstalledTreeIsGapFree is the false-positive boundary and the shape
// of every post-install scan: source present, examined, no gap.
func TestD148InstalledTreeIsGapFree(t *testing.T) {
	dir, g := d148NpmTree(t, true)
	if err := (&Adapter{}).ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("an installed tree is fully examined; got %v", err)
	}
}

// TestD148RootStaysExempt: the root's manifest is what discovery keyed on. The
// exemption exists so a graph node with npm.path "." never turns into a
// spurious gap in some flow where extraction runs against a different path.
func TestD148RootStaysExempt(t *testing.T) {
	dir := t.TempDir() // deliberately empty: not even a root package.json
	g := graph.New()
	root := g.AddNode(&graph.Node{
		ID: "pkg:npm/app@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "app", Version: "1.0.0", Attr: map[string]string{"npm.path": "."},
	})
	g.MarkRoot(root.ID)
	if err := (&Adapter{}).ExtractInstallSurface(dir, g); err != nil {
		if gaps := instsurf.GapsOf(err); len(gaps) > 0 {
			t.Errorf("the root is not a dependency; its absent manifest is not a source-unavailable gap: %v", gaps)
		}
	}
}
