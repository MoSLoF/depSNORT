package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/baseline"
)

const projFixture = "../../internal/ecosystem/npm/testdata/proj"

func TestBaselineCreateWritesLoadableProfiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "baseline.json")
	if code := run([]string{"baseline", "create", "-o", out, "-no-registry", projFixture}); code != 0 {
		t.Fatalf("baseline create exit code = %d, want 0", code)
	}

	profiles, err := baseline.Load(out)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(profiles) == 0 {
		t.Fatal("baseline recorded no profiles")
	}
	for purl, p := range profiles {
		if p.PURL != purl {
			t.Errorf("profile keyed %q carries PURL %q", purl, p.PURL)
		}
		// -no-registry means no publisher identity was available. Every profile
		// must SAY so rather than sit silently publisher-free, or a later diff
		// could read the absence as continuity.
		if !containsStr(p.Unobserved, "publisher-unavailable") {
			t.Errorf("%s: Unobserved = %v, want publisher-unavailable under -no-registry",
				purl, p.Unobserved)
		}
	}
}

// TestBaselineCreateIsDeterministic is the property that lets the file be
// committed: two runs over an unchanged tree must differ only in the timestamp.
func TestBaselineCreateIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	for _, out := range []string{a, b} {
		if code := run([]string{"baseline", "create", "-o", out, "-no-registry", projFixture}); code != 0 {
			t.Fatalf("baseline create exit code = %d", code)
		}
	}

	rawA, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	rawB, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if stripCreated(string(rawA)) != stripCreated(string(rawB)) {
		t.Errorf("two baselines of the same tree differ:\n%s\n---\n%s", rawA, rawB)
	}
}

func TestScanWithMissingBaselineIsUsageError(t *testing.T) {
	code := run([]string{"scan", "-no-osv", "-no-registry",
		"-baseline", filepath.Join(t.TempDir(), "absent.json"), projFixture})
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d: an unreadable baseline must not silently "+
			"downgrade to a scan that reports no drift", code, exitUsage)
	}
}

func TestScanWithBaselineRuns(t *testing.T) {
	out := filepath.Join(t.TempDir(), "baseline.json")
	if code := run([]string{"baseline", "create", "-o", out, "-no-registry", projFixture}); code != 0 {
		t.Fatalf("baseline create exit code = %d", code)
	}
	// Scanning the same tree the baseline was taken from: nothing drifted, so
	// the verdict must be exactly what the same scan produces without a
	// baseline. (This fixture already carries an unrelated gate-eligible
	// finding, so the assertion is "unchanged", not "zero".)
	want := run([]string{"scan", "-no-osv", "-no-registry", "-fail-on-eligible", projFixture})
	got := run([]string{"scan", "-no-osv", "-no-registry", "-fail-on-eligible",
		"-baseline", out, projFixture})
	if got != want {
		t.Errorf("scan against its own baseline exit code = %d, want %d (no drift to find)", got, want)
	}
}

func TestBaselineUnknownSubcommandIsUsageError(t *testing.T) {
	if code := run([]string{"baseline", "frobnicate"}); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if code := run([]string{"baseline"}); code != exitUsage {
		t.Errorf("bare `baseline` exit code = %d, want %d", code, exitUsage)
	}
}

func containsStr(list []string, s string) bool {
	return slices.Contains(list, s)
}

// stripCreated removes the one line a baseline is allowed to differ on.
func stripCreated(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.Contains(line, `"created"`) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
