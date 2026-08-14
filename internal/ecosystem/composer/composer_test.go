package composer

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestDetect(t *testing.T) {
	a := New()
	if !a.Detect("testdata") {
		t.Error("should detect testdata directory with composer.lock")
	}
	if !a.Detect("testdata/composer.lock") {
		t.Error("should detect testdata/composer.lock directly")
	}
	if a.Detect("testdata/nonexistent") {
		t.Error("should not detect nonexistent path")
	}
}

func TestResolve(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}

	// Expect: root + monolog/monolog + psr/log + guzzlehttp/guzzle + phpunit/phpunit = 5 nodes
	nodes := g.SortedNodes()
	if len(nodes) != 5 {
		for _, n := range nodes {
			t.Logf("  node: %s (name=%s, depth=%d, direct=%v)", n.ID, n.Name, n.Depth, n.Direct)
		}
		t.Fatalf("nodes = %d, want 5", len(nodes))
	}

	// Check that psr/log is a transitive dep via monolog and guzzle.
	psr := g.Get("pkg:composer/psr/log@3.0.0")
	if psr == nil {
		t.Fatal("psr/log node missing")
	}

	// Check monolog's dependency edge to psr/log.
	monologID := "pkg:composer/monolog/monolog@3.4.0"
	psrID := "pkg:composer/psr/log@3.0.0"
	var found bool
	for _, e := range g.SortedEdges() {
		if e.From == monologID && e.To == psrID {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing edge: monolog/monolog -> psr/log")
	}
}

func TestResolveComposerNamespace(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Composer PURL should encode vendor as namespace.
	monolog := g.Get("pkg:composer/monolog/monolog@3.4.0")
	if monolog == nil {
		t.Fatal("monolog/monolog not found by PURL with namespace")
	}
	if monolog.Name != "monolog/monolog" {
		t.Errorf("name = %q, want monolog/monolog", monolog.Name)
	}
}

// TestReMarkDirectRemovesSyntheticRootEdge covers the flat-collapse bug: every
// lockfile package used to get an unconditional root -> pkg edge that survived
// even after a real inter-package edge was drawn, so assignDepths' BFS always
// found the synthetic one-hop path first. B is only ever required by A, so it
// must end up at Depth 2 via A, not Depth 1 via a stale root edge.
func TestReMarkDirectRemovesSyntheticRootEdge(t *testing.T) {
	raw := []byte(`{
		"packages": [
			{"name": "vendor/a", "version": "1.0.0", "require": {"vendor/b": "^1.0"}},
			{"name": "vendor/b", "version": "1.0.0"}
		]
	}`)
	g, err := parseComposerLock("composer.lock", raw)
	if err != nil {
		t.Fatalf("parseComposerLock: %v", err)
	}

	aID := "pkg:composer/vendor/a@1.0.0"
	bID := "pkg:composer/vendor/b@1.0.0"

	b := g.Get(bID)
	if b == nil {
		t.Fatal("vendor/b node missing")
	}
	if b.Depth != 2 {
		t.Errorf("vendor/b Depth = %d, want 2", b.Depth)
	}
	if b.Direct {
		t.Error("vendor/b Direct = true, want false")
	}

	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}
	rootID := g.Roots[0]

	var rootToB, aToB bool
	for _, e := range g.SortedEdges() {
		if e.Type != graph.EdgeDependsOn {
			continue
		}
		if e.From == rootID && e.To == bID {
			rootToB = true
		}
		if e.From == aID && e.To == bID {
			aToB = true
		}
	}
	if rootToB {
		t.Error("root -> vendor/b edge still present, want removed")
	}
	if !aToB {
		t.Error("vendor/a -> vendor/b edge missing")
	}
}

func TestResolveDevPackages(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	phpunit := g.Get("pkg:composer/phpunit/phpunit@10.3.5")
	if phpunit == nil {
		t.Fatal("phpunit node missing")
	}
	if phpunit.Attr["composer.section"] != "packages-dev" {
		t.Errorf("phpunit section = %q, want packages-dev", phpunit.Attr["composer.section"])
	}
}
