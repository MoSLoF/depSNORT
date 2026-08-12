package ciactions

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory until it finds go.mod, so
// the test locates the workflows regardless of where `go test` is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (no go.mod found walking up)")
		}
		dir = parent
	}
}

// usesRe captures `uses: owner/repo@ref` and any trailing comment. Local (./)
// and docker:// references have no owner/@ref shape and are intentionally not
// matched.
var (
	usesRe = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*([A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@(\S+)(.*)$`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// TestEveryWorkflowActionIsPinned is the drift guard the follow-up review asked
// for (R-03 P2): documentation, the shell pin check, and the actual workflow
// files cannot diverge, because this fails the Go suite the moment any action
// reference regresses to a mutable tag or loses its version comment.
func TestEveryWorkflowActionIsPinned(t *testing.T) {
	root := repoRoot(t)
	wfDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("reading %s: %v", wfDir, err)
	}

	total := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(wfDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, m := range usesRe.FindAllStringSubmatch(string(raw), -1) {
			repo, ref, rest := m[1], m[2], strings.TrimSpace(m[3])
			total++

			if !shaRe.MatchString(ref) {
				t.Errorf("%s: %s@%s is NOT pinned to a 40-char commit SHA (mutable tag)", name, repo, ref)
				continue
			}
			// A bare SHA is unreadable to a human maintainer; require the version
			// comment Dependabot also relies on to bump the pin.
			if !strings.HasPrefix(rest, "#") || !strings.Contains(rest, "v") {
				t.Errorf("%s: %s@%s is pinned but lacks a `# vX.Y.Z` version comment (%q)", name, repo, ref, rest)
			}
		}
	}

	// Guard against a vacuous pass: if the glob or regex silently matched
	// nothing, the test would "pass" while enforcing nothing.
	if total == 0 {
		t.Fatal("found no action references to check — the workflow glob or matcher is broken")
	}
	t.Logf("verified %d workflow action reference(s) are SHA-pinned", total)
}
