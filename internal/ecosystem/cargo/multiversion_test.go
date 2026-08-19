package cargo

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/purl"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/profile"
)

// edgesFrom returns the depends-on targets of one node.
func edgesFrom(g *graph.Graph, from string) []string {
	var out []string
	for _, e := range g.SortedEdges() {
		if e.From == from && e.Type == graph.EdgeDependsOn {
			out = append(out, e.To)
		}
	}
	return out
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestParseDepSpec(t *testing.T) {
	tests := []struct {
		spec               string
		name, version, src string
	}{
		{"serde", "serde", "", ""},
		{"harbor-dupe 1.0.0", "harbor-dupe", "1.0.0", ""},
		{
			"harbor-dupe 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
			"harbor-dupe", "1.0.0", "registry+https://github.com/rust-lang/crates.io-index",
		},
		{
			"harbor-forked 0.3.0 (git+https://example.invalid/r?rev=9f1c0de#9f1c0de)",
			"harbor-forked", "0.3.0", "git+https://example.invalid/r?rev=9f1c0de#9f1c0de",
		},
	}
	for _, tt := range tests {
		got := parseDepSpec(tt.spec)
		if got.name != tt.name || got.version != tt.version || got.source != tt.src {
			t.Errorf("parseDepSpec(%q) = %+v, want name=%q version=%q source=%q",
				tt.spec, got, tt.name, tt.version, tt.src)
		}
	}
}

// TestVersionQualifiedDepConnectsOnlyToItsVersion is the DS-REV-02
// reproduction: `app` depends on harbor-dupe 1.0.0 while 2.0.0 is also in the
// lock. Before the fix, resolution was by name and produced BOTH edges.
func TestVersionQualifiedDepConnectsOnlyToItsVersion(t *testing.T) {
	g, err := New().Resolve("testdata/multiversion")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	const (
		app = "pkg:cargo/app@0.1.0"
		v1  = "pkg:cargo/harbor-dupe@1.0.0"
		v2  = "pkg:cargo/harbor-dupe@2.0.0"
		mid = "pkg:cargo/mid-crate@0.5.0"
	)

	appDeps := edgesFrom(g, app)
	if !has(appDeps, v1) {
		t.Errorf("app -> harbor-dupe@1.0.0 edge missing; app deps = %v", appDeps)
	}
	if has(appDeps, v2) {
		t.Errorf("app -> harbor-dupe@2.0.0 must NOT exist: the lock selected 1.0.0. deps = %v", appDeps)
	}

	// The other direction of the same fact: mid-crate selected 2.0.0 only.
	midDeps := edgesFrom(g, mid)
	if !has(midDeps, v2) || has(midDeps, v1) {
		t.Errorf("mid-crate deps = %v, want exactly harbor-dupe@2.0.0", midDeps)
	}

	// Depth and direct/transitive both derive from the edges, so a spurious
	// edge silently rewrites them too.
	if n := g.Get(v2); n != nil && n.Direct {
		t.Error("harbor-dupe@2.0.0 is reached only through mid-crate; it must not be direct")
	}
	if n := g.Get(v2); n != nil && n.Depth != 2 {
		t.Errorf("harbor-dupe@2.0.0 depth = %d, want 2 (app -> mid-crate -> here)", n.Depth)
	}
}

// TestSameVersionDifferentSourcesAreDistinctNodes closes the half of DS-REV-02
// that was previously deferred. A registry crate and a git fork at the same
// name@version are different code, and they are now different nodes: the PURL
// carries the origin as a qualifier, so identity reflects it.
//
// Before qualifiers the two collapsed into one node and the later entry's
// source class overwrote the earlier one's, so the node reported whichever
// source the parser happened to read last — which decides whether the advisory
// lookup for it meant anything.
func TestSameVersionDifferentSourcesAreDistinctNodes(t *testing.T) {
	g, err := New().Resolve("testdata/multiversion")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var registryID, gitID string
	for _, n := range g.SortedNodes() {
		if n.Name != "harbor-forked" {
			continue
		}
		switch class, _ := n.SourceOf(); class {
		case graph.SourceRegistry:
			registryID = n.ID
		case graph.SourceGit:
			gitID = n.ID
		}
	}
	if registryID == "" || gitID == "" {
		t.Fatalf("want a registry node AND a git node for harbor-forked; got registry=%q git=%q",
			registryID, gitID)
	}
	if registryID == gitID {
		t.Fatal("the two sources share a node ID")
	}

	// The registry copy keeps the bare, canonical coordinate: qualifying it too
	// would change the identity of nearly every package in every tree.
	if registryID != "pkg:cargo/harbor-forked@0.3.0" {
		t.Errorf("registry node ID = %q, want the bare PURL", registryID)
	}
	// The fork carries its origin, so two different forks of one crate are also
	// distinguishable from each other.
	if !strings.Contains(gitID, "source=git") || !strings.Contains(gitID, "source_ref=") {
		t.Errorf("git node ID = %q, want source and source_ref qualifiers", gitID)
	}
	if _, err := purl.Parse(gitID); err != nil {
		t.Errorf("qualified node ID does not parse as a PURL: %v", err)
	}

	// The app's dependency is qualified with the REGISTRY source, so the edge
	// must land on the registry node and not on the fork.
	deps := edgesFrom(g, "pkg:cargo/app@0.1.0")
	if !has(deps, registryID) {
		t.Errorf("app -> registry harbor-forked edge missing; deps = %v", deps)
	}
	if has(deps, gitID) {
		t.Errorf("app must not depend on the git fork; deps = %v", deps)
	}
}

// TestIdenticalIdentityIsStillAmbiguous: two entries sharing name, version AND
// source are genuinely indistinguishable — the only route is two path crates,
// since Cargo.lock records no path for them. Nothing can tell those apart, so
// the surviving node says so instead of asserting one of two answers.
func TestIdenticalIdentityIsStillAmbiguous(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "vendored"
version = "1.0.0"

[[package]]
name = "vendored"
version = "1.0.0"
`)
	g, err := parseCargoLock("testdata", lock)
	if err != nil {
		t.Fatalf("parseCargoLock: %v", err)
	}
	n := g.Get("pkg:cargo/vendored@1.0.0?source=path")
	if n == nil {
		t.Fatal("vendored node missing")
	}
	if class, _ := n.SourceOf(); class != graph.SourceUnknown {
		t.Errorf("source class = %q, want unknown for an indistinguishable pair", class)
	}
	if n.Attr["cargo.source_collision"] != "true" {
		t.Error("the collision must be recorded on the node")
	}
}

// TestAmbiguousNameOnlyDepIsDisclosed: a bare name with several candidates is
// not resolvable. Guessing would put an edge in the graph indistinguishable
// from a real one, so it becomes explicit coverage loss instead (D-24).
func TestAmbiguousNameOnlyDepIsDisclosed(t *testing.T) {
	lock := []byte(`version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "harbor-dupe",
]

[[package]]
name = "harbor-dupe"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "harbor-dupe"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	g, err := parseCargoLock("testdata", lock)
	if err != nil {
		t.Fatalf("parseCargoLock: %v", err)
	}
	if deps := edgesFrom(g, "pkg:cargo/app@0.1.0"); len(deps) != 0 {
		t.Errorf("ambiguous name-only dep produced edges %v; it must produce none", deps)
	}
	cov := g.Coverage()
	if cov.Unresolved != 1 {
		t.Errorf("Coverage.Unresolved = %d, want 1", cov.Unresolved)
	}
	if !cov.Incomplete() {
		t.Error("an unresolvable dependency must degrade coverage")
	}
}

// TestUnqualifiedDepStillResolvesWhenUnique: the common case — one version in
// the lock, no qualification needed — must keep working.
func TestUnqualifiedDepStillResolvesWhenUnique(t *testing.T) {
	g, err := New().Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if deps := edgesFrom(g, "pkg:cargo/serde@1.0.188"); !has(deps, "pkg:cargo/serde_derive@1.0.188") {
		t.Errorf("serde -> serde_derive edge missing; deps = %v", deps)
	}
	if cov := g.Coverage(); cov.Unresolved != 0 {
		t.Errorf("an unambiguous tree reported %d unresolved dep(s)", cov.Unresolved)
	}
}

// TestTopologyDigestReflectsTheCorrectEdges ties the fix to the reason it
// matters for the drift axis: the digest is computed from direct dependencies,
// so a spurious edge silently changes what a baseline comparison sees.
func TestTopologyDigestReflectsTheCorrectEdges(t *testing.T) {
	g, err := New().Resolve("testdata/multiversion")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The workspace root is a source-less crate, so it carries the ?source=path
	// qualifier every local crate gets; its provenance also rides on the
	// source_class attr. (It is selected as a root by being source-less with no
	// incoming edge — not by being Cargo.lock's alphabetically-first entry.)
	app := g.Get("pkg:cargo/app@0.1.0")
	if app == nil {
		t.Fatal("app node missing")
	}
	p := profile.FromGraph(g, app)
	if p.TopologyDigest == "" {
		t.Fatal("no topology digest computed")
	}

	// Same tree, but with the pre-fix behavior simulated by adding the edge a
	// name-only resolution would have created. The digest must differ — which
	// is precisely why the bug corrupted drift comparisons rather than merely
	// adding noise to the graph.
	g2, _ := New().Resolve("testdata/multiversion")
	g2.AddEdge("pkg:cargo/app@0.1.0", "pkg:cargo/harbor-dupe@2.0.0", graph.EdgeDependsOn)
	if profile.FromGraph(g2, g2.Get("pkg:cargo/app@0.1.0")).TopologyDigest == p.TopologyDigest {
		t.Error("topology digest is insensitive to a spurious direct edge")
	}
}
