package builtin

import (
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// The OPU-16 investigation asked one question: is advisory scoping per-NODE (every
// version present in the graph is evaluated) or per-selected-version (only the
// version a real build resolves)? These tests answer it empirically with a planted
// advisory, the confirmation the OPU-16 hand-off required before any fix.
//
// Conclusion: scoping is per-node, and per-node is correct. The graph's nodes ARE
// the selected/observed versions — one per module per resolution context after
// OPU-15 collapsed the union that used to carry superseded, never-built versions as
// extra nodes (opensnitch: 11 versions of x/sys before, one after). So a per-node
// advisory match lands on a version some resolution actually selected, not a phantom.
// The tests below pin the two halves: a planted advisory fires on exactly the
// version node it names, and a module present at two versions is evaluated at each
// independently (no per-name collapse that would hide a version-specific advisory).

// TestVC008ScopingIsPerNodeVersion plants an advisory on ONE version of a module
// that appears at two versions, and confirms the finding lands on exactly that
// version's node — never the other. This is the per-node / version-specific
// behavior: advisories are matched to (name, version), so the check evaluates the
// precise coordinate, which is what a CVE that affects only some versions requires.
func TestVC008ScopingIsPerNodeVersion(t *testing.T) {
	v1 := "pkg:npm/leftpad@1.0.0"
	v2 := "pkg:npm/leftpad@2.0.0"
	g := graph.New()
	g.AddNode(&graph.Node{ID: v1, Kind: graph.KindPackage, Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"})
	g.AddNode(&graph.Node{ID: v2, Kind: graph.KindPackage, Ecosystem: "npm", Name: "leftpad", Version: "2.0.0"})

	// Advisory planted on v1.0.0 ONLY (the version-specific case: v2.0.0 is fixed).
	fs := (KnownVuln{}).Run(&check.Context{
		Graph:      g,
		Advisories: map[string][]datasource.Advisory{v1: {{ID: "CVE-2099-0001", Source: "osv"}}},
	})
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1 (only the affected version's node)", len(fs))
	}
	if fs[0].NodeID != v1 {
		t.Errorf("finding landed on %q, want %q — advisory scoping must be version-specific, not per-name", fs[0].NodeID, v1)
	}
}

// TestVC008EvaluatesEachVersionNodeIndependently is the other half: when a module
// is present at two versions and BOTH carry an advisory, the check emits one
// finding per version node — it does not collapse by name. This is why the scoping
// is correctly per-node: a version-specific advisory on one coordinate can never be
// masked by, or merged into, a different version of the same package.
func TestVC008EvaluatesEachVersionNodeIndependently(t *testing.T) {
	v1 := "pkg:npm/leftpad@1.0.0"
	v2 := "pkg:npm/leftpad@2.0.0"
	g := graph.New()
	g.AddNode(&graph.Node{ID: v1, Kind: graph.KindPackage, Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"})
	g.AddNode(&graph.Node{ID: v2, Kind: graph.KindPackage, Ecosystem: "npm", Name: "leftpad", Version: "2.0.0"})

	fs := (KnownVuln{}).Run(&check.Context{
		Graph: g,
		Advisories: map[string][]datasource.Advisory{
			v1: {{ID: "CVE-2099-0001", Source: "osv"}},
			v2: {{ID: "CVE-2099-0002", Source: "osv"}},
		},
	})
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2 (one per version node)", len(fs))
	}
	got := map[string]bool{}
	for _, f := range fs {
		got[f.NodeID] = true
	}
	if !got[v1] || !got[v2] {
		t.Errorf("findings landed on %v, want both %q and %q", got, v1, v2)
	}
}
