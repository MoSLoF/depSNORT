package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Assessment follow-up (finding #2): ReadDir and Contains — the directory-facing
// half of the containment surface — had no direct tests, though a symlinked-out
// directory leaking its entry names is exactly the threat the doc comments name.
// Each test drives one real vector a hostile checkout can plant.

func TestReadDirListsInTreeDirectory(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "sub", "a.txt"), "a")
	mustWrite(t, filepath.Join(root, "sub", "b.txt"), "b")
	r := newReaderAt(t, root)

	entries, err := r.ReadDir("sub")
	if err != nil {
		t.Fatalf("a legitimate in-tree directory must list: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("want 2 entries, got %d", len(entries))
	}
}

func TestReadDirRefusesTraversal(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "ok", "x.txt"), "x")
	r := newReaderAt(t, root)

	if _, err := r.ReadDir("../"); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("ReadDir(\"../\") must be ErrOutsideRoot, got %v", err)
	}
	if _, err := r.ReadDir("ok/../../"); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("a disguised traversal must be ErrOutsideRoot, got %v", err)
	}
}

func TestReadDirRefusesAbsoluteOutside(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	r := newReaderAt(t, root)
	if _, err := r.ReadDir(outside); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("ReadDir of an absolute out-of-root path must be ErrOutsideRoot, got %v", err)
	}
}

func TestReadDirRefusesRegularFile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "file.txt"), "x")
	r := newReaderAt(t, root)
	if _, err := r.ReadDir("file.txt"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("ReadDir of a regular file must be ErrNotRegular, got %v", err)
	}
}

func TestReadDirRefusesSymlinkedOutDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret.txt"), "s")
	link := filepath.Join(root, "leak")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := newReaderAt(t, root)
	// The escape a symlinked-out directory enables is leaking the OUTSIDE
	// directory's entry names; containment must refuse before listing.
	if _, err := r.ReadDir("leak"); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("ReadDir through a symlinked-out directory must be ErrOutsideRoot, got %v", err)
	}
}

func TestContainsDirectoryAndBoundaries(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "sub", "a.txt"), "a")
	r := newReaderAt(t, root)

	if !r.Contains("sub") {
		t.Errorf("an in-tree directory must be contained (Contains accepts dirs, unlike Exists)")
	}
	if !r.Contains(filepath.Join(root, "sub")) {
		t.Errorf("an absolute in-tree directory must be contained")
	}
	if r.Contains("does/not/exist") {
		t.Errorf("a nonexistent path is not contained")
	}
	if r.Contains("../") {
		t.Errorf("a traversal must not be contained")
	}
}

func TestContainsRefusesSymlinkedOutDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "leak")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := newReaderAt(t, root)
	if r.Contains("leak") {
		t.Errorf("a symlink pointing out of root must not be contained")
	}
}

func TestSiblingPrefixIsNotContained(t *testing.T) {
	// within() uses a root+separator prefix check; a sibling directory that
	// merely shares a name prefix (root vs root+"EVIL") must not be treated as
	// inside root.
	base := t.TempDir()
	root := filepath.Join(base, "root")
	sibling := filepath.Join(base, "rootEVIL")
	mustWrite(t, filepath.Join(root, "keep.txt"), "k")
	mustWrite(t, filepath.Join(sibling, "secret.txt"), "s")
	r := newReaderAt(t, root)

	if r.Contains(sibling) {
		t.Errorf("a sibling sharing a name prefix must not be contained")
	}
	if _, err := r.ReadFile(filepath.Join(sibling, "secret.txt")); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("reading from a prefix-sibling directory must be ErrOutsideRoot, got %v", err)
	}
}
