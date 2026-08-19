package pypi

import (
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// OPU-13: a non-canonical requirements file (requirements-dev.txt) sitting beside
// requirements.txt, NOT pulled in via -r, is a real install-time surface that
// was silently unread before. It must now be scanned into the same project root.
func TestRequirementsSiblingsAreScanned(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask==2.0.1\n")
	writeFile(t, filepath.Join(dir, "requirements-dev.txt"), "pytest==7.4.0\n")
	writeFile(t, filepath.Join(dir, "test-requirements.txt"), "coverage==7.3.0\n")
	// A constraints file must NOT be treated as a requirements source.
	writeFile(t, filepath.Join(dir, "constraints.txt"), "urllib3==1.26.5\n")

	g, err := (&Adapter{ScanRoot: dir}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %s", n.Depth, n.ID)
	}
	for _, id := range []string{
		"pkg:pypi/flask@2.0.1",    // canonical
		"pkg:pypi/pytest@7.4.0",   // requirements-dev.txt sibling
		"pkg:pypi/coverage@7.3.0", // test-requirements.txt sibling
	} {
		if g.Get(id) == nil {
			t.Errorf("%s from a sibling requirements file was not scanned", id)
		}
	}
	// The constraints file's pin must NOT be pulled in as a requirement.
	if g.Get("pkg:pypi/urllib3@1.26.5") != nil {
		t.Error("constraints.txt must not be read as a requirements source")
	}
}

// A sibling already pulled in via -r must not be read twice, and must not be
// falsely disclosed as unread.
func TestRequirementsSiblingViaIncludeNotDoubled(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask==2.0.1\n-r requirements-dev.txt\n")
	writeFile(t, filepath.Join(dir, "requirements-dev.txt"), "pytest==7.4.0\n")

	g, err := (&Adapter{ScanRoot: dir}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Get("pkg:pypi/pytest@7.4.0") == nil {
		t.Error("pytest should be scanned")
	}
	// pytest appears once (nodes dedupe by ID); the -r'd sibling is not
	// re-scanned. Assert no unfollowed-include disclosure was produced.
	root := g.Get(g.Roots[0])
	if u := root.Attr[graph.AttrUnresolved]; u != "" {
		t.Errorf("a cleanly -r'd sibling must not be disclosed as unread; got %q", u)
	}
}

// A lone requirements.txt with no siblings stays clean — no disclosure, no
// phantom nodes.
func TestRequirementsLoneFileStaysClean(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask==2.0.1\n")

	g, err := (&Adapter{ScanRoot: dir}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if root := g.Get(g.Roots[0]); root.Attr[graph.AttrUnresolved] != "" {
		t.Errorf("a lone requirements.txt must produce no disclosure; got %q", root.Attr[graph.AttrUnresolved])
	}
	if len(g.SortedNodes()) != 2 { // root + flask
		t.Errorf("nodes = %d, want 2 (root + flask)", len(g.SortedNodes()))
	}
}

// A directory with only a non-canonical requirements file (no requirements.txt)
// is now recognized as a Python project instead of "nothing to scan", and
// pointing directly at such a file is recognized too.
func TestRequirementsNonCanonicalDetected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements-dev.txt"), "pytest==7.4.0\n")

	if !(&Adapter{}).Detect(dir) {
		t.Error("a directory with only requirements-dev.txt should be detected as a PyPI project")
	}
	if !(&Adapter{}).Detect(filepath.Join(dir, "requirements-dev.txt")) {
		t.Error("pointing directly at requirements-dev.txt should be recognized")
	}
	g, err := (&Adapter{ScanRoot: dir}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Get("pkg:pypi/pytest@7.4.0") == nil {
		t.Error("pytest from the non-canonical file was not scanned")
	}
}
