package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// hookGraphNamed builds a package with one install hook of an explicit name and
// ecosystem, carrying the given capabilities.
func hookGraphNamed(pkgID, eco, hookName string, caps ...string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: pkgID, Kind: graph.KindPackage, Ecosystem: eco, Name: "p", Version: "1.0.0"})
	hookID := "hook:" + pkgID + "#" + strings.ReplaceAll(hookName, ":", "_")
	hn := g.AddNode(&graph.Node{
		ID: hookID, Kind: graph.KindInstallHook, Ecosystem: eco, Name: hookName,
		Attr: map[string]string{"hook.package": pkgID},
	})
	for _, c := range caps {
		hn.Attr["cap."+c] = "true"
	}
	g.AddEdge(pkgID, hookID, graph.EdgeDeclaresHook)
	return g
}

// TestVC002LFiresAdvisory: an import-time hook (the telnyx _client.py shape)
// produces exactly one VC-002L finding, and it never gates.
func TestVC002LFiresAdvisory(t *testing.T) {
	g := hookGraphNamed("pkg:pypi/telnyx@4.87.1", "pypi", "import-time:telnyx/_client.py", "obfuscation", "exec")
	fs := (HookImportTime{}).Run(&check.Context{Graph: g})
	if len(fs) != 1 {
		t.Fatalf("import-time hook must produce one VC-002L finding; got %+v", fs)
	}
	if fs[0].GateClass != finding.GateAdvisory {
		t.Errorf("VC-002L must be advisory (never gates), got %v", fs[0].GateClass)
	}
}

// TestImportTimeExcludedFromBlockFamily is the D-165 guarantee: an import-time
// hook carrying the exfil combo (credentials+network) must NOT fire VC-002d
// (block) — the block-class family excludes these hooks — while VC-002L still
// surfaces it as advisory.
func TestImportTimeExcludedFromBlockFamily(t *testing.T) {
	g := hookGraphNamed("pkg:pypi/telnyx@4.87.1", "pypi", "import-time:telnyx/_client.py", "credentials", "network")

	if fs := (HookExfilCapable{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("VC-002d must not fire on an import-time hook (advisory-only, D-165); got %+v", fs)
	}
	if fs := (HookImportTime{}).Run(&check.Context{Graph: g}); len(fs) != 1 {
		t.Errorf("VC-002L should surface the import-time exfil combo as advisory; got %+v", fs)
	}
}

// TestModuleLoadNotExcluded pins that the exclusion is scoped to "import-time:"
// only: npm's "module-load:" entry-module hooks (VC-002j's surface) still reach
// the block-class family, so the D-165 carve-out does not disarm OPU-31.
func TestModuleLoadNotExcluded(t *testing.T) {
	g := hookGraphNamed("pkg:npm/x@1.0.0", "npm", "module-load:index.js", "credentials", "network")
	if fs := (HookExfilCapable{}).Run(&check.Context{Graph: g}); len(fs) != 1 {
		t.Errorf("npm module-load hooks must still gate via VC-002d; got %+v", fs)
	}
}
