package composer

import (
	"testing"
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
