package npm

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestResolveFixture(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/proj")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// root + express + send + mime + @scope/util = 5 nodes (send is deduped).
	if g.Len() != 5 {
		t.Fatalf("node count = %d, want 5", g.Len())
	}

	// Expected depends-on edges.
	if got := len(g.Edges); got != 5 {
		t.Errorf("edge count = %d, want 5", got)
	}

	// Root marked.
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want exactly one", g.Roots)
	}

	// The scoped package carries the install-hook FACT and correct PURL.
	util := g.Get("pkg:npm/%40scope/util@2.0.1")
	if util == nil {
		t.Fatal("missing @scope/util node")
	}
	if util.Attr["npm.hasInstallScript"] != "true" {
		t.Errorf("@scope/util hasInstallScript not recorded: %+v", util.Attr)
	}
	if !util.Direct {
		t.Errorf("@scope/util should be a direct dependency")
	}

	// Nested hoisting: express's mime resolves to the nested 1.6.0 entry.
	if mime := g.Get("pkg:npm/mime@1.6.0"); mime == nil {
		t.Error("missing hoisted mime@1.6.0 node")
	} else if mime.Depth != 2 {
		t.Errorf("mime depth = %d, want 2", mime.Depth)
	}

	// send is a single deduped node reached from both express and @scope/util.
	send := g.Get("pkg:npm/send@0.18.0")
	if send == nil {
		t.Fatal("missing send node")
	}
	var incoming int
	for _, e := range g.Edges {
		if e.To == send.ID && e.Type == graph.EdgeDependsOn {
			incoming++
		}
	}
	if incoming != 2 {
		t.Errorf("send incoming depends-on edges = %d, want 2", incoming)
	}
}

func TestDetect(t *testing.T) {
	a := &Adapter{}
	if !a.Detect("testdata/proj") {
		t.Error("Detect should match a dir containing package-lock.json")
	}
	if a.Detect("testdata") {
		t.Error("Detect should not match a dir without a lockfile")
	}
}

// A real workspace scan reported a resolve failure for a project whose lockfile
// declares no dependencies at all. That is a legitimate, clean project — not a
// parse error — and failing it understated coverage.
func TestResolveDependencyFreeLockfile(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/emptylock")
	if err != nil {
		t.Fatalf("a dependency-free lockfile must resolve, got: %v", err)
	}
	if g.Len() != 1 {
		t.Fatalf("nodes = %d, want 1 (the root alone)", g.Len())
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}
	root := g.Get(g.Roots[0])
	if root == nil || root.Name != "no-deps-project" || root.Version != "1.4.2" {
		t.Errorf("root node wrong: %+v", root)
	}
	if len(g.Edges) != 0 {
		t.Errorf("edges = %d, want 0", len(g.Edges))
	}
}

// Genuinely malformed input must still fail loudly.
func TestResolveRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Adapter{}).Resolve(dir); err == nil {
		t.Error("malformed JSON should still be an error")
	}
}

// A real 59-repo workspace scan showed 2,687 of 5,371 packages stranded at
// depth 0 with no inbound edge. Cause: the root's devDependencies produced
// nodes but never edges, so each devDep dragged its whole transitive subtree
// out of reach of the root.
func TestRootDevDependenciesAreLinked(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/withdev")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	root := g.Roots[0]

	devTool := "pkg:npm/dev-tool@2.0.0"
	var linked bool
	for _, e := range g.SortedEdges() {
		if e.From == root && e.To == devTool {
			linked = true
		}
	}
	if !linked {
		t.Error("root devDependency has no inbound edge — its subtree is stranded")
	}
	if n := g.Get(devTool); n == nil || n.Depth != 1 {
		t.Errorf("dev-tool depth = %v, want 1", n)
	}
	// Its own transitive dependency must now be reachable too.
	if n := g.Get("pkg:npm/dev-sub@1.0.0"); n == nil || n.Depth != 2 {
		t.Errorf("dev-sub depth = %v, want 2 (reachable via dev-tool)", n)
	}
	// The dev marker is recorded as a fact.
	if n := g.Get(devTool); n == nil || n.Attr["npm.dev"] != "true" {
		t.Errorf("dev flag not recorded: %+v", n)
	}

	// Nothing except the root may be stranded.
	inbound := map[string]bool{}
	for _, e := range g.SortedEdges() {
		inbound[e.To] = true
	}
	for _, n := range g.SortedNodes() {
		if n.ID == root {
			continue
		}
		if !inbound[n.ID] && n.Name != "never-installed" {
			t.Errorf("orphaned node with no inbound edge: %s", n.ID)
		}
	}
}

// ---- lockfileVersion 1 coverage -------------------------------------------

// resolveV1 handles the older nested "dependencies" format used by npm v5/v6.
// This fixture mirrors the proj fixture's structure as a v1 lockfile.
func TestResolveV1Lockfile(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/v1lock")
	if err != nil {
		t.Fatalf("Resolve v1: %v", err)
	}
	// root + express + send + mime + @scope/util = 5 nodes.
	if g.Len() != 5 {
		t.Fatalf("v1 node count = %d, want 5", g.Len())
	}
	if len(g.Roots) != 1 {
		t.Fatalf("v1 roots = %d, want 1", len(g.Roots))
	}

	// The scoped package is resolved correctly.
	util := g.Get("pkg:npm/%40scope/util@2.0.1")
	if util == nil {
		t.Fatal("v1: missing @scope/util node")
	}
	if !util.Direct {
		t.Error("v1: @scope/util should be a direct dependency")
	}

	// Nested mime is present and reachable.
	mime := g.Get("pkg:npm/mime@1.6.0")
	if mime == nil {
		t.Fatal("v1: missing mime@1.6.0")
	}
	if mime.Depth != 2 {
		t.Errorf("v1: mime depth = %d, want 2", mime.Depth)
	}
	if mime.Direct {
		t.Error("v1: mime should NOT be a direct dependency")
	}

	// Edges: root->express, root->send, root->@scope/util, express->mime
	// (nested), express->send (via requires), @scope/util->send (via requires).
	if len(g.Edges) != 6 {
		t.Errorf("v1 edge count = %d, want 6", len(g.Edges))
	}
}

// A DEPENDENCY's own devDependencies are never installed by npm, so they must
// NOT become edges — otherwise the graph claims packages that are not present.
func TestTransitiveDevDependenciesAreNotLinked(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/withdev")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range g.SortedEdges() {
		if e.To == "pkg:npm/never-installed@9.0.0" {
			t.Errorf("a dependency's devDependency was linked: %s -> %s", e.From, e.To)
		}
	}
}

// npm 7+ auto-installs peerDependencies, so they are genuine edges. Without
// them a peer sits in the lockfile unreachable: a real workspace scan stranded
// `konva` (a peer of `react-konva`), `monaco-editor` and `@react-three/fiber`
// this way.
func TestPeerDependenciesAreLinked(t *testing.T) {
	g, err := (&Adapter{}).Resolve("testdata/withpeer")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var linked bool
	for _, e := range g.SortedEdges() {
		if e.From == "pkg:npm/react-konva@18.2.10" && e.To == "pkg:npm/konva@9.2.1" {
			linked = true
		}
	}
	if !linked {
		t.Error("peerDependency produced no edge — the peer is stranded")
	}
	if n := g.Get("pkg:npm/konva@9.2.1"); n == nil || n.Depth != 2 {
		t.Errorf("konva depth = %v, want 2 (root -> react-konva -> konva)", n)
	}
}
