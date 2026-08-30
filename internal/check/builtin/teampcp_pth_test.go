package builtin

// Track-A validation for the TeamPCP litellm 1.82.8 .pth vector: the analyzer
// half is asserted in internal/ecosystem/pypi/installsurface_test.go
// (TestAnalyzePythonLitellmInitPth / ...BenignBootstrapPth); these two pin the
// CHECK outcome on the resulting hook, so the whole path — .pth line to verdict —
// is covered on both the malicious and the benign side.

import (
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// pthHookGraph builds a pypi package with one pth:import install hook carrying
// the given capabilities.
func pthHookGraph(pkgID string, caps ...string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: pkgID, Kind: graph.KindPackage, Ecosystem: "pypi", Name: "p", Version: "1.0.0"})
	hookID := "hook:" + pkgID + "#pth:import"
	hn := g.AddNode(&graph.Node{ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "pypi", Name: "pth:import"})
	if hn.Attr == nil {
		hn.Attr = map[string]string{}
	}
	for _, c := range caps {
		hn.Attr["cap."+c] = "true"
	}
	g.AddEdge(pkgID, hookID, graph.EdgeDeclaresHook)
	return g
}

// TestVC002eFiresOnLitellmPth: the litellm .pth shape (base64 decode + exec)
// resolves to obfuscation+exec, which must produce exactly one VC-002e
// decode-and-execute finding at gate-eligible severity.
func TestVC002eFiresOnLitellmPth(t *testing.T) {
	g := pthHookGraph("pkg:pypi/litellm@1.82.8", "obfuscation", "exec")
	fs := (HookObfuscated{}).Run(&check.Context{Graph: g})
	if len(fs) != 1 {
		t.Fatalf("litellm .pth (obfuscation+exec) must fire one VC-002e finding; got %+v", fs)
	}
	if fs[0].GateClass != finding.GateEligible {
		t.Errorf("VC-002e gate class = %v, want gate-eligible (decode-and-execute is not, alone, block-class)", fs[0].GateClass)
	}
}

// TestVC002eQuietOnBenignPth: a benign bootstrap-import .pth carries exec only
// (the analyzer's deliberate lower bound on any import line) and must NOT fire
// VC-002e. This is the false-positive boundary the litellm case sits beyond.
func TestVC002eQuietOnBenignPth(t *testing.T) {
	g := pthHookGraph("pkg:pypi/goodpkg@1.0.0", "exec")
	if fs := (HookObfuscated{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("exec-only pth must not fire VC-002e; got %+v", fs)
	}
}
