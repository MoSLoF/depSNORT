package versiondrift

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory until it finds go.mod, so
// the test locates the docs regardless of where `go test` is invoked from.
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

var (
	// pyprojectVersionRe mirrors the sed both the Makefile and release.yml use
	// (`sed -n 's/^version = "\(.*\)"/\1/p'`): anchored at column 0, the literal
	// ` = "` spacing, greedy to the last quote on the line.
	pyprojectVersionRe = regexp.MustCompile(`(?m)^version = "(.*)"$`)

	// readmeVersionRe matches a release-version literal in prose or in a code
	// fence. Two deliberate properties:
	//
	//   - The leading `v` is REQUIRED, matching the grep docs/RELEASING.md
	//     already documents. It is what excludes the false positives: "Requires
	//     Go 1.24+" in the README, and third-party examples of the
	//     lodash@4.17.21 shape that fill docs/DECISIONS.md and could migrate
	//     into the README later.
	//   - The trailing class accepts a PEP 440 pre-release suffix but stops at a
	//     hyphen, so "v0.8.0rc1" matches whole while
	//     "depsnort-v0.7.5-linux-amd64" yields just "v0.7.5". Without it, a
	//     future 0.8.0rc1 release would fail against a literal this pattern had
	//     itself truncated.
	readmeVersionRe = regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.]*`)
)

// TestREADMEVersionLiteralsMatchPyproject is the drift guard for the one place
// the single-source rule does not reach. Scope is README.md ONLY, and that is
// the substantive judgement here — every other version literal in the repo is
// deliberately frozen and must NOT be forced to track the current release:
//
//   - docs/DECISIONS.md — historical entries ("Released as v0.7.3") and
//     third-party package examples
//   - docs/RELEASING.md — vX.Y.Z placeholders and the v0.7.3 post-mortem
//   - docs/PERFORMANCE.md — "## Baseline (vX.Y.Z)" records WHEN the numbers were
//     measured; forcing it to track would corrupt the document at the next bump,
//     and its cross-release comparisons name v0.7.3 on purpose
//
// There is no exemption mechanism, matching internal/ciactions. If a future
// README genuinely needs a frozen v-prefixed version, narrowing this test is
// the deliberate act that should be required.
func TestREADMEVersionLiteralsMatchPyproject(t *testing.T) {
	root := repoRoot(t)

	pyprojectPath := filepath.Join(root, "pyproject.toml")
	raw, err := os.ReadFile(pyprojectPath)
	if err != nil {
		t.Fatalf("reading %s: %v", pyprojectPath, err)
	}

	// The shell equivalent uses `sed -n …p`, which PRINTS EVERY MATCH rather
	// than stopping at the first. A second column-0 `version = "…"` line would
	// therefore silently corrupt the version release.yml gates the tag against.
	// Nothing else checks this, so assert it here.
	matches := pyprojectVersionRe.FindAllStringSubmatch(string(raw), -1)
	if len(matches) != 1 {
		t.Fatalf("pyproject.toml has %d column-0 `version = \"...\"` lines, want exactly 1; "+
			"the Makefile and release.yml extract it with `sed -n ...p`, which prints every "+
			"match and would silently concatenate them", len(matches))
	}
	want := "v" + matches[0][1]

	readmePath := filepath.Join(root, "README.md")
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}

	total := 0
	for i, line := range strings.Split(string(readme), "\n") {
		for _, got := range readmeVersionRe.FindAllString(line, -1) {
			total++
			if got != want {
				t.Errorf("README.md:%d: version literal %s does not match pyproject.toml (%s) — "+
					"a release bump edited pyproject.toml without updating the README, which ships "+
					"a README advertising the previous release", i+1, got, want)
			}
		}
	}

	// Guard against a vacuous pass: if the pattern silently matched nothing, or
	// the literals were removed outright, the test would "pass" while enforcing
	// nothing.
	if total == 0 {
		t.Fatal("found no version literals in README.md to check — the matcher is broken, " +
			"or the literals docs/RELEASING.md step 1 tells you to bump have been removed")
	}
	t.Logf("verified %d README.md version literal(s) track pyproject.toml (%s)", total, want)
}
