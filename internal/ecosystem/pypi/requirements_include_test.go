package pypi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// OPU-07: a requirements.txt that splits its pins into `-r`/`-c` includes must
// have those files followed, not silently skipped. Before this, only the top
// file's visible lines were parsed and every `-r other.txt` was dropped with no
// disclosure — so a project could present a few clean pins while the bulk (and
// any poisoned pin) lived unseen in an included file.
func TestRequirementsFollowsIncludes(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "proj")
	mustMkdir(t, filepath.Join(root, "requirements"))

	// A pin that lives OUTSIDE the scan root; an escaping include must never reach
	// it.
	writeFile(t, filepath.Join(base, "escape.txt"), "secret-exfil==9.9.9\n")

	// The top file: one visible pin, then includes — a sub-file, a nested -c, a
	// remote URL, and a path escaping the root.
	writeFile(t, filepath.Join(root, "requirements.txt"),
		"flask==2.0.1\n"+
			"-r requirements/prod.txt\n"+
			"-r https://example.com/evil.txt\n"+
			"-r ../escape.txt\n")
	// The included file carries the bulk — including a pin an attacker would hide
	// here — and itself pulls in a constraints file.
	writeFile(t, filepath.Join(root, "requirements", "prod.txt"),
		"poisoned==6.6.6\n-c ../constraints.txt\n")
	writeFile(t, filepath.Join(root, "constraints.txt"), "urllib3==1.26.5\n")

	a := &Adapter{ScanRoot: root}
	g, err := a.Resolve(root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %s", n.Depth, n.ID)
	}

	// The whole point: pins reached only through the includes are now nodes.
	for _, id := range []string{
		"pkg:pypi/flask@2.0.1",    // top file
		"pkg:pypi/poisoned@6.6.6", // -r requirements/prod.txt
		"pkg:pypi/urllib3@1.26.5", // -c ../constraints.txt, nested one level deeper
	} {
		if g.Get(id) == nil {
			t.Errorf("pin %s from a followed include was not discovered", id)
		}
	}

	// The escaping include must NOT have been read.
	if g.Get("pkg:pypi/secret-exfil@9.9.9") != nil {
		t.Error("an include escaping the scan root was followed — containment breach")
	}

	// The unfollowable includes (URL, escape) must be DISCLOSED as coverage gaps,
	// never silently dropped.
	unres := ""
	for _, r := range g.Roots {
		if n := g.Get(r); n != nil {
			unres = n.Attr[graph.AttrUnresolved]
		}
	}
	if !strings.Contains(unres, "unfollowed-include") {
		t.Errorf("unfollowed includes not disclosed; AttrUnresolved = %q", unres)
	}
	if !strings.Contains(unres, "remote URL") {
		t.Errorf("URL include not disclosed as such; AttrUnresolved = %q", unres)
	}
	if !strings.Contains(unres, "outside scan root") {
		t.Errorf("escaping include not disclosed as such; AttrUnresolved = %q", unres)
	}
}

// A cyclic include chain (a -> b -> a) must terminate and parse each file once.
func TestRequirementsIncludeCycleTerminates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "requirements.txt"), "a-pkg==1.0\n-r b.txt\n")
	writeFile(t, filepath.Join(root, "b.txt"), "b-pkg==2.0\n-r requirements.txt\n")

	a := &Adapter{ScanRoot: root}
	g, err := a.Resolve(root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Get("pkg:pypi/a-pkg@1.0") == nil || g.Get("pkg:pypi/b-pkg@2.0") == nil {
		t.Error("a cyclic include chain should still parse both files' pins")
	}
}

// With no containment root available, includes cannot be safely followed — each
// must be disclosed, never silently skipped and never read.
func TestRequirementsIncludeDisclosedWithoutRoot(t *testing.T) {
	g, err := parseRequirements("requirements.txt", []byte("flask==2.0.1\n-r prod.txt\n"), "requirements.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	unres := ""
	for _, r := range g.Roots {
		if n := g.Get(r); n != nil {
			unres = n.Attr[graph.AttrUnresolved]
		}
	}
	if !strings.Contains(unres, "unfollowed-include") {
		t.Errorf("include with no containment root must be disclosed; got %q", unres)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
