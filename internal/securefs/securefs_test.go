package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-03. Each test drives one real escape vector a hostile checkout can plant,
// and asserts the reader refuses it while still serving legitimate in-tree reads.

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newReaderAt(t *testing.T, root string) *Reader {
	t.Helper()
	r, err := NewReader(root)
	if err != nil {
		t.Fatalf("NewReader(%q): %v", root, err)
	}
	return r
}

func TestReadsLegitimateInTreeFile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "pkg", "package.json"), `{"name":"ok"}`)
	r := newReaderAt(t, root)

	// Absolute in-tree.
	b, err := r.ReadFile(filepath.Join(root, "pkg", "package.json"))
	if err != nil || string(b) != `{"name":"ok"}` {
		t.Fatalf("absolute in-tree read: b=%q err=%v", b, err)
	}
	// Relative to root.
	b, err = r.ReadFile(filepath.Join("pkg", "package.json"))
	if err != nil || string(b) != `{"name":"ok"}` {
		t.Fatalf("relative in-tree read: b=%q err=%v", b, err)
	}
}

func TestRejectsTraversalEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "secret.txt")
	mustWrite(t, outside, "TOP SECRET")
	r := newReaderAt(t, root)

	if _, err := r.ReadFile(filepath.Join("..", "secret.txt")); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("../ escape: err=%v, want ErrOutsideRoot", err)
	}
	// A deeper, disguised traversal that cleans back out of the tree.
	if _, err := r.ReadFile("pkg/../../secret.txt"); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("disguised traversal: err=%v, want ErrOutsideRoot", err)
	}
}

func TestRejectsAbsoluteOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere.txt")
	mustWrite(t, outside, "not yours")
	r := newReaderAt(t, root)

	if _, err := r.ReadFile(outside); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("absolute-outside: err=%v, want ErrOutsideRoot", err)
	}
}

func TestRejectsFileSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target.txt")
	mustWrite(t, outside, "exfil me")
	link := filepath.Join(root, "innocent.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := newReaderAt(t, root)

	if _, err := r.ReadFile("innocent.json"); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("file symlink escape: err=%v, want ErrOutsideRoot", err)
	}
}

func TestRejectsDirectorySymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outDir := t.TempDir()
	mustWrite(t, filepath.Join(outDir, "package.json"), `{"name":"evil"}`)
	link := filepath.Join(root, "vendor")
	if err := os.Symlink(outDir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := newReaderAt(t, root)

	if _, err := r.ReadFile(filepath.Join("vendor", "package.json")); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("directory symlink escape: err=%v, want ErrOutsideRoot", err)
	}
}

func TestAllowsContainedSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real", "package.json")
	mustWrite(t, real, `{"name":"contained"}`)
	link := filepath.Join(root, "alias.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := newReaderAt(t, root)

	b, err := r.ReadFile("alias.json")
	if err != nil || string(b) != `{"name":"contained"}` {
		t.Fatalf("a symlink pointing inside root must be allowed: b=%q err=%v", b, err)
	}
}

func TestRefusesNonRegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := newReaderAt(t, root)

	if _, err := r.ReadFile("adir"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory read: err=%v, want ErrNotRegular", err)
	}
}

func TestEnforcesSizeLimit(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "big.txt"), strings.Repeat("A", 4096))
	r := newReaderAt(t, root)
	r.maxBytes = 1024 // white-box: shrink the cap for the test

	if _, err := r.ReadFile("big.txt"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized read: err=%v, want ErrTooLarge", err)
	}
}

func TestMissingFileIsNotExistNotEscape(t *testing.T) {
	root := t.TempDir()
	r := newReaderAt(t, root)

	_, err := r.ReadFile("nope.json")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing optional file: err=%v, want os.ErrNotExist", err)
	}
	if errors.Is(err, ErrOutsideRoot) {
		t.Fatal("a missing in-tree file must not look like an escape")
	}
}

func TestExists(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "here.txt"), "x")
	r := newReaderAt(t, root)

	if !r.Exists("here.txt") {
		t.Error("Exists must be true for an in-tree regular file")
	}
	if r.Exists("gone.txt") {
		t.Error("Exists must be false for a missing file")
	}
	if r.Exists(filepath.Join("..", "anything")) {
		t.Error("Exists must be false for an escaping path")
	}
}
