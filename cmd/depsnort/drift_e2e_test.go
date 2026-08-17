package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/verdict"
)

const (
	driftBaseFixture      = "../../internal/ecosystem/npm/testdata/drift-base"
	driftCandidateFixture = "../../internal/ecosystem/npm/testdata/drift-candidate"
)

// scanJSON runs a scan into a temp file and decodes the report.
func scanJSON(t *testing.T, args ...string) verdict.Result {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	full := append([]string{"scan", "-no-osv", "-no-registry", "-o", out}, args...)
	run(full)

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	var report struct {
		Verdict verdict.Result `json:"verdict"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decoding report: %v", err)
	}
	return report.Verdict
}

func findingsBy(res verdict.Result, checkID string) []finding.Finding {
	var out []finding.Finding
	for _, f := range res.Findings {
		if f.CheckID == checkID {
			out = append(out, f)
		}
	}
	return out
}

// TestDriftEndToEnd walks the whole workflow the market review asked for: take
// a baseline of a tree, then scan the same tree one patch release later, where
// the patch release acquired credential access and network egress inside a hook
// it already had.
func TestDriftEndToEnd(t *testing.T) {
	base := filepath.Join(t.TempDir(), "baseline.json")
	if code := run([]string{"baseline", "create", "-o", base, "-no-registry", driftBaseFixture}); code != 0 {
		t.Fatalf("baseline create exit code = %d", code)
	}

	res := scanJSON(t, "-baseline", base, driftCandidateFixture)
	drift := findingsBy(res, "VC-010")
	if len(drift) != 1 {
		t.Fatalf("VC-010 findings = %d, want exactly 1 (only one package drifted)", len(drift))
	}
	f := drift[0]

	if f.NodeID != "pkg:npm/depsnort-fixture-drift@1.6.3" {
		t.Errorf("drift reported against %q", f.NodeID)
	}
	if f.GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible: a patch release gained credential access", f.GateClass)
	}
	for _, want := range []string{"credentials", "network", "NPM_TOKEN", "telemetry.example.invalid", "patch"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("evidence missing %q:\n%s", want, f.Evidence)
		}
	}

	// The unchanged package in the same tree must be silent. A drift axis that
	// fires on everything is a drift axis nobody reads.
	for _, d := range drift {
		if strings.Contains(d.NodeID, "depsnort-fixture-stable") {
			t.Errorf("VC-010 fired on an unchanged package: %+v", d)
		}
	}
}

// TestScanningTheBaselineTreeItselfReportsNoDrift: the same tree the baseline
// was taken from has, by construction, drifted from nothing.
func TestScanningTheBaselineTreeItselfReportsNoDrift(t *testing.T) {
	base := filepath.Join(t.TempDir(), "baseline.json")
	if code := run([]string{"baseline", "create", "-o", base, "-no-registry", driftBaseFixture}); code != 0 {
		t.Fatalf("baseline create exit code = %d", code)
	}
	res := scanJSON(t, "-baseline", base, driftBaseFixture)
	if got := findingsBy(res, "VC-010"); len(got) != 0 {
		t.Errorf("VC-010 fired against the tree its own baseline was taken from: %+v", got)
	}
}

// TestDriftIsInactiveWithoutABaseline: the candidate tree on its own produces
// the VC-002 findings it deserves and no drift finding at all, because there is
// nothing to compare against.
func TestDriftIsInactiveWithoutABaseline(t *testing.T) {
	res := scanJSON(t, driftCandidateFixture)
	if got := findingsBy(res, "VC-010"); len(got) != 0 {
		t.Errorf("VC-010 fired with no baseline: %+v", got)
	}
	if got := findingsBy(res, "VC-002d"); len(got) == 0 {
		t.Error("VC-002d should still judge the exfil-capable hook on its own merits")
	}
}
