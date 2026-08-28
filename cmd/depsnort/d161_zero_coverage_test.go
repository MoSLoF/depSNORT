package main

// D-161 regression: pointing the tool at a repo whose only dependency manifest
// is unrecognized must not read as a clean pass. Live on swytchdb/swytch.jepsen,
// a project.clj declaring a JDBC driver with three real advisories produced
// "no supported projects found" at exit 0 — with -fail-on-incomplete set. The
// D-59 machinery (recognized manifest → incomplete coverage → exit 3 under the
// gate) already existed; the Clojure names were simply absent from the tables.
// -require-project covers the remaining shape D-59 cannot: a directory with NO
// recognized manifest at all (a deleted or renamed go.mod in a CI job that
// expects one), where the deliberate empty-repo-sweep clean exit is wrong.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const leinProject = `(defproject swytch.jepsen "0.1.0"
  :dependencies [[org.clojure/clojure "1.12.4"]
                 [org.postgresql/postgresql "42.7.4"]])
`

// D-162 superseded the D-161 shape this test originally pinned: project.clj
// is now CLAIMED and RESOLVED by the clojure adapter, so the jepsen fixture
// scans as a real project (fully pinned, flat-by-format) instead of a gap.
// The D-161 gap behavior itself is still pinned below on pom.xml, a manifest
// that remains recognized-but-unread.
func TestClojureManifestNowResolves(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "project.clj"), []byte(leinProject), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	if code := run([]string{"scan", "-no-osv", "-no-registry", "-out", out, dir}); code != 0 {
		t.Errorf("scan of a pinned project.clj repo: exit = %d, want 0", code)
	}
	// Not just a clean exit: the manifest must actually RESOLVE — the pinned
	// JDBC driver present as a maven node. Without this the test would pass
	// vacuously if the adapter were unregistered (nothing-to-scan is also 0).
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no verdict written — project.clj was not scanned: %v", err)
	}
	if !strings.Contains(string(raw), "pkg:maven/org.postgresql/postgresql@42.7.4") {
		t.Error("resolved graph must contain the pinned postgresql coordinate")
	}
	// Fully pinned direct deps: nothing unresolved, and flat resolution is a
	// format limitation (the Pipfile.lock precedent, D-24) — it discloses, it
	// does not gate.
	if code := run([]string{"scan", "-no-osv", "-no-registry", "-fail-on-incomplete", dir}); code != 0 {
		t.Errorf("-fail-on-incomplete on a fully-pinned project.clj: exit = %d, want 0", code)
	}
}

func TestUnreadManifestIsIncompleteCoverageNotCleanPass(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<project><groupId>x</groupId></project>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Without the gate: disclosed, advisory-tier, still exit 0.
	if code := run([]string{"scan", "-no-osv", "-no-registry", dir}); code != 0 {
		t.Errorf("ungated scan of a gap-only repo: exit = %d, want 0 (disclosure, not a gate)", code)
	}
	// With the gate: the recognized-but-unread manifest is degraded coverage.
	if code := run([]string{"scan", "-no-osv", "-no-registry", "-fail-on-incomplete", dir}); code != 3 {
		t.Errorf("-fail-on-incomplete on a pom.xml repo: exit = %d, want 3 (zero-coverage repos must not pass the coverage gate)", code)
	}
}

func TestRequireProjectFailsOnNothingToScan(t *testing.T) {
	empty := t.TempDir()
	// The default stays deliberate: a sweep across repos is not failed by an
	// empty one, gate or no gate.
	if code := run([]string{"scan", "-no-osv", "-no-registry", empty}); code != 0 {
		t.Errorf("empty dir: exit = %d, want 0", code)
	}
	if code := run([]string{"scan", "-no-osv", "-no-registry", "-fail-on-incomplete", empty}); code != 0 {
		t.Errorf("empty dir with -fail-on-incomplete: exit = %d, want 0 (nothing was expected here)", code)
	}
	// -require-project inverts it, in both discovery modes.
	if code := run([]string{"scan", "-no-osv", "-no-registry", "-require-project", empty}); code != 3 {
		t.Errorf("empty dir with -require-project: exit = %d, want 3", code)
	}
	if code := run([]string{"scan", "-no-osv", "-no-registry", "-require-project", "-no-recursive", empty}); code != 3 {
		t.Errorf("empty dir with -require-project -no-recursive: exit = %d, want 3", code)
	}
}

func TestRequireProjectPassesWhenAProjectExists(t *testing.T) {
	if code := run([]string{"scan", "-no-osv", "-no-registry", "-require-project",
		"../../internal/ecosystem/npm/testdata/emptylock"}); code != 0 {
		t.Errorf("-require-project on a real project: exit = %d, want 0", code)
	}
}
