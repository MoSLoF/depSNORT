package composer

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// OPU-11: a composer.json with a real require block and no sibling composer.lock
// must be claimed and scanned manifest-only, not read as "nothing to scan".
func TestComposerManifestOnly(t *testing.T) {
	dir := t.TempDir()
	writeComposerFile(t, filepath.Join(dir, "composer.json"), `{
	  "name": "acme/app",
	  "require": {
	    "php": "^8.1",
	    "ext-json": "*",
	    "guzzlehttp/guzzle": "^7.0",
	    "monolog/monolog": "^3.0"
	  }
	}`)

	a := New()
	if !a.Detect(dir) {
		t.Fatal("a composer.json with a require block must be detected")
	}
	g, err := a.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want one", g.Roots)
	}
	root := g.Get(g.Roots[0])
	got := map[string]string{}
	for _, d := range root.DeclaredDepsOf() {
		got[d.Name] = d.Constraint
	}
	// The two real packages are declared; php and ext-json are platform tokens.
	if len(got) != 2 {
		t.Fatalf("declared deps = %v, want guzzle + monolog only", got)
	}
	if got["guzzlehttp/guzzle"] != "^7.0" {
		t.Errorf("guzzle constraint = %q, want ^7.0", got["guzzlehttp/guzzle"])
	}
	if got["monolog/monolog"] != "^3.0" {
		t.Errorf("monolog constraint = %q, want ^3.0", got["monolog/monolog"])
	}
	if _, ok := got["php"]; ok {
		t.Error("php (a platform token) must not be a declared dependency")
	}
	// No php/ext package node was materialized.
	for _, n := range g.SortedNodes() {
		if n.Name == "php" || n.Name == "ext-json" {
			t.Errorf("platform token %q must not become a node", n.Name)
		}
	}
	// Manifest-only coverage is disclosed, not a silent clean.
	if root.Attr[graph.AttrFlatResolution] != "composer" || root.Attr[graph.AttrUnresolvedCount] != "2" {
		t.Errorf("manifest coverage not disclosed: %+v", root.Attr)
	}
}

// A composer.lock present alongside composer.json still resolves from the lock:
// observed versions beat presumed, no manifest-only regression.
func TestComposerLockTakesPrecedenceOverManifest(t *testing.T) {
	dir := t.TempDir()
	writeComposerFile(t, filepath.Join(dir, "composer.json"), `{"require":{"monolog/monolog":"^3.0"}}`)
	writeComposerFile(t, filepath.Join(dir, "composer.lock"), `{
	  "packages": [
	    {"name": "monolog/monolog", "version": "3.5.0", "dist": {"type": "zip", "url": "https://x/m.zip"}}
	  ]
	}`)

	g, err := New().Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The lock's observed version is present, and it is an OBSERVED package node,
	// not a manifest declared-dep.
	if g.Get("pkg:composer/monolog/monolog@3.5.0") == nil {
		t.Error("lock precedence lost: observed monolog@3.5.0 not resolved")
	}
	if g.Get(g.Roots[0]).Attr[graph.AttrFlatResolution] == "composer" {
		t.Error("a locked project must not be marked manifest-only flat-resolution")
	}
}

// A composer.json declaring only platform requirements is not a resolvable
// project, and must never emit a php node.
func TestComposerPlatformOnlyManifestNotAProject(t *testing.T) {
	dir := t.TempDir()
	writeComposerFile(t, filepath.Join(dir, "composer.json"), `{"require":{"php":"^8.1","ext-mbstring":"*"}}`)

	if New().Detect(dir) {
		t.Error("a platform-only composer.json declares no installable deps and is not a project")
	}
}

func writeComposerFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
