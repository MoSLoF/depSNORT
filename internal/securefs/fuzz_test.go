package securefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzReadFileContainment drives arbitrary attacker-chosen path strings at the
// contained reader and asserts the SECURITY INVARIANT, not merely the absence of
// a panic: no input may ever yield the contents of a file outside the scan root
// (D-33 / F-03).
//
// The fixture is deliberately adversarial: the outside file carries a sentinel
// string, and there is a symlink inside the root pointing at it. If any fuzzed
// path — traversal, absolute, symlink, encoded, or something stranger — causes
// ReadFile to return that sentinel, containment is broken and the test fails.
func FuzzReadFileContainment(f *testing.F) {
	root := f.TempDir()
	outsideDir := f.TempDir()

	const sentinel = "OUTSIDE-ROOT-SENTINEL-MUST-NEVER-BE-READ"
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte(sentinel), 0o644); err != nil {
		f.Fatal(err)
	}
	// A legitimate in-tree file, so the reader has something valid to return.
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("in-tree"), 0o644); err != nil {
		f.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		f.Fatal(err)
	}
	// Escape hatches planted inside the root, exactly as a hostile checkout would.
	_ = os.Symlink(outsideFile, filepath.Join(root, "link.txt"))
	_ = os.Symlink(outsideDir, filepath.Join(root, "linkdir"))

	r, err := NewReader(root)
	if err != nil {
		f.Fatal(err)
	}

	seeds := []string{
		"ok.txt", "sub/ok.txt", "link.txt", "linkdir/secret.txt",
		"../secret.txt", "../../secret.txt", "sub/../../secret.txt",
		outsideFile, "/etc/passwd", "", ".", "..", "./ok.txt",
		"sub/./../ok.txt", `..\secret.txt`, "ok.txt\x00.png",
		strings.Repeat("../", 40) + "etc/passwd",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, p string) {
		b, err := r.ReadFile(p)
		if err != nil {
			return // refusing is always an acceptable outcome
		}
		if strings.Contains(string(b), sentinel) {
			t.Fatalf("CONTAINMENT BREACH: ReadFile(%q) returned out-of-root content", p)
		}
		// A successful read must also be a real, contained, regular file.
		if !r.Exists(p) {
			t.Fatalf("ReadFile(%q) succeeded but Exists reports false", p)
		}
	})
}
