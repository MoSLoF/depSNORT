package builtin

// Decisions D-28 (download-cradle block) and D-29 (IOC ledger match).

import (
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource/ioc"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// hookGraph builds a package with one install hook carrying the given caps.
func hookGraph(pkgID string, caps ...string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: pkgID, Kind: graph.KindPackage, Ecosystem: "npm", Name: "p", Version: "1.0.0"})
	hookID := "hook:" + pkgID + "#postinstall"
	hn := g.AddNode(&graph.Node{ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "npm", Name: "postinstall"})
	if hn.Attr == nil {
		hn.Attr = map[string]string{}
	}
	for _, c := range caps {
		hn.Attr["cap."+c] = "true"
	}
	g.AddEdge(pkgID, hookID, graph.EdgeDeclaresHook)
	return g
}

func TestVC002fCradleBlocks(t *testing.T) {
	g := hookGraph("pkg:npm/cradle@1.0.0", "cradle", "network", "exec")
	fs := (HookDownloadCradle{}).Run(&check.Context{Graph: g})
	if len(fs) != 1 || fs[0].GateClass != finding.GateBlock {
		t.Fatalf("a download-cradle hook must produce one block finding; got %+v", fs)
	}
}

func TestVC002bDefersToCradle(t *testing.T) {
	g := hookGraph("pkg:npm/cradle@1.0.0", "cradle", "network", "exec")
	if fs := (HookNetwork{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("VC-002b must defer to VC-002f when a cradle is present; got %+v", fs)
	}
}

func TestVC002bStillFiresWithoutCradle(t *testing.T) {
	g := hookGraph("pkg:npm/dl@1.0.0", "network")
	if fs := (HookNetwork{}).Run(&check.Context{Graph: g}); len(fs) != 1 {
		t.Errorf("plain network egress must still fire VC-002b; got %+v", fs)
	}
}

func TestVC003BlocksOnLedgerMatch(t *testing.T) {
	g := graph.New()
	id := "pkg:npm/left-pad@1.3.0"
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})

	ctx := &check.Context{Graph: g, IOC: map[string]ioc.Indicator{
		id: {Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Severity: "critical", Reference: "INC-2026-014"},
	}}
	fs := (IOCMatch{}).Run(ctx)
	if len(fs) != 1 || fs[0].GateClass != finding.GateBlock || fs[0].Confidence != 1.0 {
		t.Fatalf("an IOC-ledger match must block with full confidence; got %+v", fs)
	}
}

func TestVC003SilentWithoutLedger(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/x@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm", Name: "x", Version: "1.0.0"})
	if fs := (IOCMatch{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("VC-003 must be silent when no ledger is supplied; got %+v", fs)
	}
}
