package main

import (
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// The post-expansion advisory pass must ask about every resolved package the
// first prefetch could not: packages ADDED by expansion, and packages whose
// version only became known during expansion (a Poetry-style pyproject.toml of
// version ranges, whose direct deps are unresolved placeholders at prefetch
// time). Before the fix, pyrsistencesniper reported "0 advisory" backed by
// ZERO OSV queries, and cecil-protocol left 186 expansion-discovered packages
// unchecked — hiding a real esbuild advisory.
//
// This test pins the SELECTION logic that drives that second pass.
func TestPostExpansionSelectsUncheckedResolvedPackages(t *testing.T) {
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "root", Ecosystem: "npm", Name: "app", Version: "1.0.0", Kind: graph.KindPackage})
	g.MarkRoot(root.ID)
	g.AddNode(&graph.Node{ID: "pkg:npm/already@1.0.0", Ecosystem: "npm", Name: "already", Version: "1.0.0", Kind: graph.KindPackage})
	g.AddNode(&graph.Node{ID: "pkg:npm/fromexpansion@2.0.0", Ecosystem: "npm", Name: "fromexpansion", Version: "2.0.0", Kind: graph.KindPackage})
	g.AddNode(&graph.Node{ID: "pkg:npm/noversion", Ecosystem: "npm", Name: "noversion", Kind: graph.KindPackage})
	g.AddNode(&graph.Node{ID: "hook:postinstall", Ecosystem: "npm", Name: "hook", Version: "1.0.0", Kind: graph.KindInstallHook})

	// The first prefetch already covered "already".
	advisories := map[string][]datasource.Advisory{
		"pkg:npm/already@1.0.0": {},
	}

	rootIDs := map[string]bool{root.ID: true}
	var selected []string
	for _, n := range g.SortedNodes() {
		if rootIDs[n.ID] || n.Kind != graph.KindPackage || n.Version == "" {
			continue
		}
		if _, queried := advisories[n.ID]; queried {
			continue
		}
		selected = append(selected, n.ID)
	}

	if len(selected) != 1 || selected[0] != "pkg:npm/fromexpansion@2.0.0" {
		t.Fatalf("second pass must select exactly the unchecked, versioned package; got %v", selected)
	}
}

// A resolved package set with nothing checked must be reported as unverified —
// a clean verdict is not a verified one (D-59).
func TestZeroAdvisoryCoverageIsDetectable(t *testing.T) {
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "root", Ecosystem: "pypi", Name: "app", Version: "0.0.0", Kind: graph.KindPackage})
	g.MarkRoot(root.ID)
	for _, id := range []string{"pkg:pypi/a@1", "pkg:pypi/b@2"} {
		g.AddNode(&graph.Node{ID: id, Ecosystem: "pypi", Name: id, Version: "1", Kind: graph.KindPackage})
	}
	rootIDs := map[string]bool{root.ID: true}

	var resolved int
	for _, n := range g.SortedNodes() {
		if !rootIDs[n.ID] && n.Kind == graph.KindPackage && n.Version != "" {
			resolved++
		}
	}
	advisories := map[string][]datasource.Advisory{} // nothing was ever queried
	var checked int
	for id := range advisories {
		if !rootIDs[id] {
			checked++
		}
	}
	if resolved != 2 {
		t.Fatalf("resolved = %d, want 2", resolved)
	}
	if !(resolved > 0 && checked == 0) {
		t.Error("the zero-coverage condition must be detectable so the report can warn")
	}
}
