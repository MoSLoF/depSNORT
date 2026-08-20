package builtin

import (
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// buildHookGraph creates a minimal graph with one package that declares an
// install hook carrying the given capabilities. This is the substrate every
// VC-002 family check reads.
func buildHookGraph(caps map[string]bool) *graph.Graph {
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:npm/suspect@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "npm", Name: "suspect", Version: "1.0.0",
	})
	hookAttr := map[string]string{}
	for c := range caps {
		hookAttr["cap."+c] = "true"
	}
	g.AddNode(&graph.Node{
		ID: "hook:pkg:npm/suspect@1.0.0#postinstall", Kind: graph.KindInstallHook,
		Ecosystem: "npm", Name: "postinstall", Attr: hookAttr,
	})
	g.AddEdge(pkg.ID, "hook:pkg:npm/suspect@1.0.0#postinstall", graph.EdgeDeclaresHook)
	return g
}

func ctx(g *graph.Graph) *check.Context {
	return &check.Context{Graph: g, Now: time.Now()}
}

func countFindings(chk check.Check, g *graph.Graph) int {
	return len(chk.Run(ctx(g)))
}

// ---- VC-002b: network-only triggers HookNetwork, not HookCredentials --------

func TestHookNetworkFiresOnNetworkOnly(t *testing.T) {
	g := buildHookGraph(map[string]bool{"network": true})
	findings := (HookNetwork{}).Run(ctx(g))
	if len(findings) != 1 {
		t.Fatalf("HookNetwork: want 1, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != "VC-002b" {
		t.Errorf("check id = %q", f.CheckID)
	}
	if f.GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible", f.GateClass)
	}
}

func TestHookNetworkSilentWhenCredentialsPresent(t *testing.T) {
	g := buildHookGraph(map[string]bool{"network": true, "credentials": true})
	if n := countFindings(HookNetwork{}, g); n != 0 {
		t.Errorf("HookNetwork should defer to VC-002d when credentials present, got %d", n)
	}
}

func TestHookNetworkSilentOnCleanTree(t *testing.T) {
	g := buildHookGraph(map[string]bool{})
	if n := countFindings(HookNetwork{}, g); n != 0 {
		t.Errorf("HookNetwork should not fire without network cap, got %d", n)
	}
}

// ---- VC-002c: credentials-only triggers HookCredentials ---------------------

func TestHookCredentialsFiresOnCredentialsOnly(t *testing.T) {
	g := buildHookGraph(map[string]bool{"credentials": true})
	findings := (HookCredentials{}).Run(ctx(g))
	if len(findings) != 1 {
		t.Fatalf("HookCredentials: want 1, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != "VC-002c" {
		t.Errorf("check id = %q", f.CheckID)
	}
	if f.Severity != finding.SevHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
}

func TestHookCredentialsSilentWhenNetworkPresent(t *testing.T) {
	g := buildHookGraph(map[string]bool{"credentials": true, "network": true})
	if n := countFindings(HookCredentials{}, g); n != 0 {
		t.Errorf("HookCredentials should defer to VC-002d when network present, got %d", n)
	}
}

// ---- VC-002d: network+credentials triggers HookExfilCapable -----------------

func TestHookExfilCapableFiresOnNetworkAndCredentials(t *testing.T) {
	g := buildHookGraph(map[string]bool{"network": true, "credentials": true})
	findings := (HookExfilCapable{}).Run(ctx(g))
	if len(findings) != 1 {
		t.Fatalf("HookExfilCapable: want 1, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != "VC-002d" {
		t.Errorf("check id = %q", f.CheckID)
	}
	if f.GateClass != finding.GateBlock {
		t.Errorf("gate class = %q, want block", f.GateClass)
	}
	if f.Confidence != 0.85 {
		t.Errorf("confidence = %g, want 0.85", f.Confidence)
	}
}

func TestHookExfilCapableObfuscationBoost(t *testing.T) {
	g := buildHookGraph(map[string]bool{"network": true, "credentials": true, "obfuscation": true})
	findings := (HookExfilCapable{}).Run(ctx(g))
	if len(findings) != 1 {
		t.Fatalf("want 1, got %d", len(findings))
	}
	if findings[0].Confidence != 0.95 {
		t.Errorf("obfuscation should boost confidence to 0.95, got %g", findings[0].Confidence)
	}
}

func TestHookExfilCapableSilentWithoutBothCaps(t *testing.T) {
	for _, caps := range []map[string]bool{
		{"network": true},
		{"credentials": true},
		{},
	} {
		if n := countFindings(HookExfilCapable{}, buildHookGraph(caps)); n != 0 {
			t.Errorf("HookExfilCapable should not fire with caps %v, got %d", caps, n)
		}
	}
}

// ---- VC-002e: obfuscation+exec triggers HookObfuscated ---------------------

func TestHookObfuscatedFiresOnObfuscationAndExec(t *testing.T) {
	g := buildHookGraph(map[string]bool{"obfuscation": true, "exec": true})
	findings := (HookObfuscated{}).Run(ctx(g))
	if len(findings) != 1 {
		t.Fatalf("HookObfuscated: want 1, got %d", len(findings))
	}
	if findings[0].CheckID != "VC-002e" {
		t.Errorf("check id = %q", findings[0].CheckID)
	}
}

func TestHookObfuscatedSilentWithoutBothCaps(t *testing.T) {
	for _, caps := range []map[string]bool{
		{"obfuscation": true},
		{"exec": true},
		{},
	} {
		if n := countFindings(HookObfuscated{}, buildHookGraph(caps)); n != 0 {
			t.Errorf("HookObfuscated should not fire with caps %v, got %d", caps, n)
		}
	}
}

// ---- mutual exclusion: the full combination fires the right checks ----------

func TestFullCapsFiresExfilAndObfuscated(t *testing.T) {
	g := buildHookGraph(map[string]bool{
		"network": true, "credentials": true, "obfuscation": true, "exec": true,
	})
	var d, e int
	for _, f := range (HookExfilCapable{}).Run(ctx(g)) {
		if f.CheckID == "VC-002d" {
			d++
		}
	}
	for _, f := range (HookObfuscated{}).Run(ctx(g)) {
		if f.CheckID == "VC-002e" {
			e++
		}
	}
	// VC-002b and VC-002c defer to VC-002d; VC-002e fires independently.
	if d != 1 {
		t.Errorf("VC-002d count = %d, want 1", d)
	}
	if e != 1 {
		t.Errorf("VC-002e count = %d, want 1", e)
	}
	if n := countFindings(HookNetwork{}, g); n != 0 {
		t.Errorf("VC-002b should be suppressed, got %d", n)
	}
	if n := countFindings(HookCredentials{}, g); n != 0 {
		t.Errorf("VC-002c should be suppressed, got %d", n)
	}
}

// buildPersistenceHookGraph builds a hook graph carrying cap.filesystem plus the
// given evidence markers (as the analyzer records them: comma-joined on the hook
// node), the substrate VC-002g reads.
func buildPersistenceHookGraph(evidence string) *graph.Graph {
	g := graph.New()
	pkg := g.AddNode(&graph.Node{
		ID: "pkg:pypi/suspect@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "suspect", Version: "1.0.0",
	})
	g.AddNode(&graph.Node{
		ID: "hook:pkg:pypi/suspect@1.0.0#setup.py", Kind: graph.KindInstallHook,
		Ecosystem: "pypi", Name: "setup.py:module-level",
		Attr: map[string]string{"cap.filesystem": "true", "hook.evidence": evidence},
	})
	g.AddEdge(pkg.ID, "hook:pkg:pypi/suspect@1.0.0#setup.py", graph.EdgeDeclaresHook)
	return g
}

// ---- VC-002g: install-hook persistence -------------------------------------

func TestHookPersistenceFiresOnPersistenceMarker(t *testing.T) {
	g := buildPersistenceHookGraph("crontab")
	findings := (HookPersistence{}).Run(ctx(g))
	if len(findings) != 1 {
		t.Fatalf("HookPersistence: want 1, got %d", len(findings))
	}
	f := findings[0]
	if f.CheckID != "VC-002g" {
		t.Errorf("check id = %q, want VC-002g", f.CheckID)
	}
	if f.Severity != finding.SevHigh || f.GateClass != finding.GateEligible {
		t.Errorf("severity/gate = %q/%q, want high/gate-eligible", f.Severity, f.GateClass)
	}
}

// The discriminating case: a filesystem write that is NOT persistence (an ordinary
// site-packages/.pth install write) must not fire VC-002g. Without the marker
// split this would false-positive on every package that writes into site-packages.
func TestHookPersistenceSilentOnBenignInstallWrite(t *testing.T) {
	g := buildPersistenceHookGraph("site-packages,.pth")
	if n := countFindings(HookPersistence{}, g); n != 0 {
		t.Errorf("HookPersistence must not fire on a benign site-packages/.pth write, got %d", n)
	}
}

func TestHookPersistenceSilentWithoutFilesystemCap(t *testing.T) {
	g := buildHookGraph(map[string]bool{"network": true})
	if n := countFindings(HookPersistence{}, g); n != 0 {
		t.Errorf("HookPersistence must not fire without filesystem cap, got %d", n)
	}
}

// Mixed evidence — a persistence marker alongside a benign one — still fires: the
// benign write does not launder the cron install sitting next to it.
func TestHookPersistenceFiresOnMixedEvidence(t *testing.T) {
	g := buildPersistenceHookGraph("site-packages,systemctl")
	if n := countFindings(HookPersistence{}, g); n != 1 {
		t.Errorf("HookPersistence should fire when a persistence marker is present among benign ones, got %d", n)
	}
}
