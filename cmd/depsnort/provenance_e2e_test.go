package main

import (
	"testing"

	"ihbv.io/depsnort/internal/verdict"
)

const vendoredFixture = "../../internal/ecosystem/cargo/testdata/vendored"

// TestVendoredSourcesReachTheExitCode is the end-to-end form of D-41. The
// fixture is shaped after the field case: a graph that is almost entirely
// crates.io, plus two in-tree vendored forks and one git dependency. Nothing in
// it is malicious, so the scan finds nothing — and that is exactly the outcome
// this test exists to keep honest. "Found nothing" over packages no advisory
// feed has ever indexed is not an all-clear, and an operator who asked to fail
// on incomplete coverage must be told.
func TestVendoredSourcesReachTheExitCode(t *testing.T) {
	if code := run([]string{"scan", "-no-osv", "-no-registry", vendoredFixture}); code != 0 {
		t.Errorf("scan exit code = %d, want 0 (nothing here is a finding)", code)
	}
	code := run([]string{"scan", "-no-osv", "-no-registry", "-fail-on-incomplete", vendoredFixture})
	if code != verdict.ExitIncomplete {
		t.Errorf("with -fail-on-incomplete, exit code = %d, want %d", code, verdict.ExitIncomplete)
	}
}
