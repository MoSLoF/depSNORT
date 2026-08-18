package osv

import (
	"encoding/json"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// The shipped fallback dataset is a security control, not a convenience cache:
// it is what an offline scan consults INSTEAD of a live VC-001 malicious-package
// check. These tests assert what it must provide, not merely that the loader
// does not crash.
//
// The test this replaced asserted the dataset "starts empty" and looked up one
// coordinate that happened to be absent. It passed for months while the shipped
// file grew to 22 coordinates and 156 advisories — none of them malicious
// (finding DS-REV-01). An invariant nobody can fail is not an invariant.

func loadShipped(t *testing.T) bundledFile {
	t.Helper()
	var f bundledFile
	if err := json.Unmarshal(bundledSnapshotRaw, &f); err != nil {
		t.Fatalf("the embedded dataset does not parse: %v", err)
	}
	return f
}

// TestBundledDatasetCarriesMaliciousIntelligence is the finding DS-REV-01 guard.
// The tier is documented, reported, and gated as malicious-package coverage; a
// dataset of ordinary CVEs cannot deliver that no matter how large it is.
func TestBundledDatasetCarriesMaliciousIntelligence(t *testing.T) {
	f := loadShipped(t)
	if len(f.Entries) == 0 {
		t.Skip("no dataset shipped in this build; nothing claims coverage either")
	}

	malicious, total := 0, 0
	ecosystems := map[string]bool{}
	for _, e := range f.Entries {
		ecosystems[e.Ecosystem] = true
		for _, a := range e.Advisories {
			total++
			if a.Malicious || datasource.ClassifyMalicious(a.ID) {
				malicious++
			}
		}
	}

	if malicious == 0 {
		t.Errorf("the shipped dataset holds %d advisories across %d coordinates but ZERO "+
			"malicious-package records; the fallback tier is documented as offline VC-001 "+
			"coverage and cannot provide it from ordinary CVEs alone (DS-REV-01)",
			total, len(f.Entries))
	}
	if len(ecosystems) < 2 {
		t.Errorf("dataset covers %d ecosystem(s) (%v); a single-ecosystem fallback silently "+
			"leaves every other ecosystem uncovered while reporting a healthy tier",
			len(ecosystems), ecosystems)
	}
}

// TestBundledEntriesAreNonEmpty: an entry with no advisories at all is worse
// than an absent one — it occupies a coordinate and answers nothing.
func TestBundledEntriesAreNonEmpty(t *testing.T) {
	for _, e := range loadShipped(t).Entries {
		if len(e.Advisories) == 0 {
			t.Errorf("%s/%s@%s is present with zero advisories", e.Ecosystem, e.Name, e.Version)
		}
		if e.Ecosystem == "" || e.Name == "" || e.Version == "" {
			t.Errorf("entry with incomplete coordinate: %+v", e)
		}
	}
}

// TestBundledGeneratedAtIsSane checks the timestamp is present and not in the
// future.
//
// Deliberately NOT a freshness assertion. A test demanding "newer than N days"
// fails on an untouched repository and has to be edited to stay green, which is
// the hardcoded-date time bomb this project has already removed once. Staleness
// is a RUNTIME disclosure — BundledDatasetAt rides on every bundled hit and the
// CLI prints its age — so the reader of a scan sees it, and the test guards the
// field's integrity instead of the calendar.
func TestBundledGeneratedAtIsSane(t *testing.T) {
	f := loadShipped(t)
	if len(f.Entries) == 0 {
		return
	}
	if f.GeneratedAt.IsZero() {
		t.Fatal("dataset ships entries with no generated_at; its age cannot be disclosed")
	}
	if f.GeneratedAt.After(time.Now().Add(24 * time.Hour)) {
		t.Errorf("generated_at %s is in the future", f.GeneratedAt)
	}
}

// TestCVEOnlyEntryIsNotMaliciousCoverage locks the accounting rule itself,
// independently of whatever the shipped file happens to contain.
func TestCVEOnlyEntryIsNotMaliciousCoverage(t *testing.T) {
	cveOnly := []datasource.Advisory{
		{ID: "GHSA-aaaa-bbbb-cccc", Summary: "ordinary vulnerability"},
		{ID: "CVE-2026-1234", Summary: "also ordinary"},
	}
	if hasMalicious(cveOnly) {
		t.Error("a CVE-only entry must not count as malicious-package coverage")
	}

	withMal := append(append([]datasource.Advisory{}, cveOnly...),
		datasource.Advisory{ID: "MAL-2026-9999", Summary: "malicious package"})
	if !hasMalicious(withMal) {
		t.Error("an entry carrying a MAL-* advisory must count as malicious coverage")
	}

	// The stored flag is honored even when the ID does not follow the MAL-*
	// convention, so a snapshot from a source that classifies differently is
	// not silently downgraded.
	if !hasMalicious([]datasource.Advisory{{ID: "OSV-2026-1", Malicious: true}}) {
		t.Error("an advisory explicitly flagged Malicious must count")
	}
	if hasMalicious(nil) {
		t.Error("no advisories cannot be malicious coverage")
	}
}

// TestBundledLookupMissIsAGap: a coordinate absent from the dataset must not
// resolve.
func TestBundledLookupMissIsAGap(t *testing.T) {
	if adv, _, ok := BundledLookup("npm|depsnort-fixture-absent|9.9.9"); ok {
		t.Errorf("BundledLookup invented a hit for an absent coordinate: %+v", adv)
	}
}
