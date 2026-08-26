package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// D-152: VC-002k, the propagation phase. depSNORT detected the credential phase
// (VC-002c/d) and the persistence phase (VC-002g); the step between them — the
// hook that PUBLISHES, turning one compromised package into many — had no
// detector, and graph.EdgeRepublish ("worm loop back into the declared tree")
// was defined, gated on, and rendered while nothing ever created one.

func d152Graph(t *testing.T, hookName, script string) *graph.Graph {
	t.Helper()
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:npm/wormy@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "wormy", Version: "1.0.0",
	})
	g.MarkRoot(pkg.ID)
	surface := installsurface.Analyze(map[string]string{hookName: script}, nil)
	instsurf.AddToGraph(g, pkg, surface)
	return g
}

// d152VC002k runs the SHIPPING check pack — builtin.Default(), the single
// registration point (D-37) — and keeps the VC-002k findings. Calling
// HookSelfPropagation{}.Run directly would pass even if the check were never
// registered, which is a check that detects nothing in production; going
// through Default() makes the registration itself load-bearing.
func d152VC002k(t *testing.T, g *graph.Graph) []finding.Finding {
	t.Helper()
	var out []finding.Finding
	for _, f := range Default().RunAll(&check.Context{Graph: g}) {
		if f.CheckID == "VC-002k" {
			out = append(out, f)
		}
	}
	return out
}

func d152Findings(t *testing.T, g *graph.Graph) []string {
	t.Helper()
	var ids []string
	for _, f := range d152VC002k(t, g) {
		ids = append(ids, f.CheckID+":"+f.Title)
	}
	return ids
}

// TestD152PublishingHookFiresVC002k is the detection itself.
func TestD152PublishingHookFiresVC002k(t *testing.T) {
	g := d152Graph(t, "postinstall", "node -e \"require('child_process').execSync('npm publish --access public')\"")
	got := d152Findings(t, g)
	if len(got) != 1 {
		t.Fatalf("a publishing install hook must fire VC-002k exactly once, got %v", got)
	}
	if !strings.Contains(got[0], "publishes to a package registry") {
		t.Errorf("unexpected title: %q", got[0])
	}
}

// TestD152RepublishEdgeIsFinallyDrawn: the edge the graph vocabulary has carried
// unused since it was written. A finding alone would leave the worm chain
// invisible in a graph view.
func TestD152RepublishEdgeIsFinallyDrawn(t *testing.T) {
	g := d152Graph(t, "postinstall", "cp.execSync('npm publish')")
	found := false
	for _, e := range g.Edges {
		if e.Type == graph.EdgeRepublish {
			if e.To != "pkg:npm/wormy@1.0.0" {
				t.Errorf("the republish edge must point back at the package (the loop), got %q", e.To)
			}
			found = true
		}
	}
	if !found {
		t.Error("a propagating hook must create a graph.EdgeRepublish edge")
	}
}

// TestD152RepublishEdgeFollowsThePayloadScript is the regression for the defect
// live validation caught and the unit tests had masked. The real Shai-Hulud
// shape puts an unremarkable `node ./harvest.js` in the hook command and the
// publish inside the referenced script. Gating the edge on the hook's own
// capabilities drew it only for a publish inlined into the command — the one
// form the attack does not take — so a real worm produced a VC-002k finding
// while the graph showed no loop at all.
func TestD152RepublishEdgeFollowsThePayloadScript(t *testing.T) {
	payload := map[string][]byte{
		"harvest.js": []byte("const cp=require('child_process');\ncp.execSync('npm publish --access public');\n"),
	}
	read := installsurface.FileReader(func(rel string) ([]byte, bool) {
		b, ok := payload[strings.TrimPrefix(rel, "./")]
		return b, ok
	})
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:npm/wormy@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "wormy", Version: "1.0.0",
	})
	g.MarkRoot(pkg.ID)
	surface := installsurface.Analyze(map[string]string{"postinstall": "node ./harvest.js"}, read)
	instsurf.AddToGraph(g, pkg, surface)

	// Precondition: the hook command itself carries no propagate capability, so
	// this test cannot pass through the inline path.
	for _, h := range surface.Hooks {
		for _, c := range h.Caps {
			if c == installsurface.CapPropagate {
				t.Fatal("fixture invalid: the hook command must not itself publish")
			}
		}
	}
	var found bool
	for _, e := range g.Edges {
		if e.Type == graph.EdgeRepublish && e.To == pkg.ID {
			found = true
		}
	}
	if !found {
		t.Error("a publish inside the hook's payload script must still draw the republish edge")
	}
	if got := d152Findings(t, g); len(got) != 1 {
		t.Errorf("VC-002k must fire for a payload-script publish, got %v", got)
	}
}

// TestD152OrdinaryHookDrawsNoRepublishEdge is the boundary: the edge must appear
// only for propagation, or the graph view fills with meaningless loops.
func TestD152OrdinaryHookDrawsNoRepublishEdge(t *testing.T) {
	g := d152Graph(t, "postinstall", "node-gyp rebuild")
	for _, e := range g.Edges {
		if e.Type == graph.EdgeRepublish {
			t.Errorf("an ordinary build hook must not create a republish edge: %+v", e)
		}
	}
	if got := d152Findings(t, g); len(got) != 0 {
		t.Errorf("an ordinary build hook must not fire VC-002k, got %v", got)
	}
}

// TestD152DryRunDoesNotFire carries the capability-layer boundary up to the
// check: a release rehearsal must not be reported as a worm.
func TestD152DryRunDoesNotFire(t *testing.T) {
	g := d152Graph(t, "postinstall", "npm publish --dry-run")
	if got := d152Findings(t, g); len(got) != 0 {
		t.Errorf("a --dry-run rehearsal must not fire VC-002k, got %v", got)
	}
}

// TestD152FullWormLoopIsNamed: publish + credential access is the complete loop
// (harvest a token, publish with it). The evidence must say so — the operator
// needs to know their registry tokens are burned, not merely that a hook
// published.
func TestD152FullWormLoopIsNamed(t *testing.T) {
	g := d152Graph(t, "postinstall",
		"const t=process.env.NPM_TOKEN; require('child_process').execSync('npm publish');")
	fs := d152VC002k(t, g)
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Evidence, "full worm loop") {
		t.Errorf("publish + credentials must be named as the worm loop, got %q", fs[0].Evidence)
	}
	if !strings.Contains(fs[0].Remediation, "Rotate") {
		t.Errorf("remediation must tell the operator to rotate tokens, got %q", fs[0].Remediation)
	}
}

// TestD152IsCriticalAndBlocking: unlike network egress, a publishing install
// hook has no benign reading.
func TestD152IsCriticalAndBlocking(t *testing.T) {
	m := (HookSelfPropagation{}).Meta()
	if m.ID != "VC-002k" || m.DefaultSeverity != finding.SevCritical || m.DefaultGate != finding.GateBlock {
		t.Errorf("declared VC-002k must be critical+block, got %s %s %s", m.ID, m.DefaultSeverity, m.DefaultGate)
	}
	// The declared Meta and the EMITTED finding are separate literals in the
	// source; asserting only Meta lets the emitted severity be downgraded
	// silently, and the emitted value is the one the gate reads.
	fs := d152VC002k(t, d152Graph(t, "postinstall", "cp.execSync('npm publish')"))
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	if fs[0].Severity != finding.SevCritical || fs[0].GateClass != finding.GateBlock {
		t.Errorf("emitted VC-002k must be critical+block, got %s %s", fs[0].Severity, fs[0].GateClass)
	}
}
