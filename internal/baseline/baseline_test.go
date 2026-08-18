package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/profile"
)

func prof(name, version string, caps ...string) profile.Profile {
	return profile.Profile{
		Schema: profile.Schema, PURL: "pkg:npm/" + name + "@" + version,
		Ecosystem: "npm", Name: name, Version: version, Caps: caps,
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	in := []profile.Profile{
		prof("zeta", "1.0.0", "exec"),
		prof("alpha", "2.3.4", "network"),
	}
	created := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	if err := Write(path, "depsnort v0.7.5", created, in); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d profiles, want 2", len(got))
	}
	if p := got["pkg:npm/alpha@2.3.4"]; len(p.Caps) != 1 || p.Caps[0] != "network" {
		t.Errorf("alpha profile did not survive the round trip: %+v", p)
	}
}

// TestWriteIsByteStable is the property that lets a baseline be committed: two
// writes of the same scan must produce identical bytes, or every scan would
// generate diff churn and reviewers would learn to ignore the file.
func TestWriteIsByteStable(t *testing.T) {
	dir := t.TempDir()
	in := []profile.Profile{
		prof("zeta", "1.0.0", "exec"),
		prof("alpha", "2.3.4", "network"),
		prof("mid", "0.1.0"),
	}
	shuffled := []profile.Profile{in[2], in[0], in[1]}
	created := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	if err := Write(a, "depsnort", created, in); err != nil {
		t.Fatalf("Write a: %v", err)
	}
	if err := Write(b, "depsnort", created, shuffled); err != nil {
		t.Fatalf("Write b: %v", err)
	}

	rawA, _ := os.ReadFile(a)
	rawB, _ := os.ReadFile(b)
	if string(rawA) != string(rawB) {
		t.Errorf("baseline is not byte-stable across input order:\n%s\n---\n%s", rawA, rawB)
	}
	if !strings.Contains(string(rawA), `"created": "2026-08-17T12:00:00Z"`) {
		t.Error("the timestamp must be confined to the created field, in UTC")
	}
}

// TestUnknownSchemaIsRefused: an operator who passed -baseline asked for drift
// to be evaluated. Quietly evaluating nothing and exiting 0 is the failure this
// package exists to prevent.
func TestUnknownSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(path, []byte(`{"schema":"depsnort.baseline/0","profiles":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("a baseline written under an unknown schema must be refused, not ignored")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("error should name the schema mismatch, got: %v", err)
	}
}

func TestLoadRejectsMissingAndIrregularFiles(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("a missing baseline must be an error")
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("a directory must not load as a baseline")
	}
}

// TestIndexPreservesEveryApprovedVersion is the DS-REV-03 guard. The previous
// implementation kept one profile per key by PURL order, so a baseline holding
// 2.0.0 and 10.0.0 selected 2.0.0 — lexicographically "10" precedes "2" — and a
// workspace where two projects approved different versions silently lost one.
func TestIndexPreservesEveryApprovedVersion(t *testing.T) {
	profiles := map[string]profile.Profile{
		"pkg:npm/dup@2.0.0":  prof("dup", "2.0.0", "exec"),
		"pkg:npm/dup@10.0.0": prof("dup", "10.0.0", "network"),
		"pkg:npm/solo@1.0.0": prof("solo", "1.0.0"),
	}
	idx := Index(profiles)

	dup := idx[Key("npm", "dup")]
	if len(dup) != 2 {
		t.Fatalf("Index kept %d profile(s) for dup, want both approved versions", len(dup))
	}
	if got := Versions(dup); got[0] != "10.0.0" || got[1] != "2.0.0" {
		t.Errorf("Versions = %v, want both versions listed", got)
	}
	if len(idx[Key("npm", "solo")]) != 1 {
		t.Error("a single-version package must still index to exactly one profile")
	}

	if amb := AmbiguousKeys(idx); len(amb) != 1 || amb[0] != Key("npm", "dup") {
		t.Errorf("AmbiguousKeys = %v, want just the duplicated key", amb)
	}
}

// TestLookupRefusesToChooseBetweenVersions: with several approved versions and
// no exact match, there is no answer — only a guess, and a guess here reports
// drift that is an artifact of the choice.
func TestLookupRefusesToChooseBetweenVersions(t *testing.T) {
	candidates := []profile.Profile{
		prof("dup", "2.0.0", "exec"),
		prof("dup", "10.0.0", "network"),
	}

	if _, ok := Lookup(candidates, "pkg:npm/dup@3.0.0", "3.0.0"); ok {
		t.Error("Lookup resolved an ambiguous baseline; it must decline")
	}

	// An exact match is not ambiguous: this version IS approved, so there is
	// nothing to compare and no drift by construction.
	got, ok := Lookup(candidates, "pkg:npm/dup@10.0.0", "10.0.0")
	if !ok || got.Version != "10.0.0" {
		t.Errorf("Lookup(exact) = (%+v, %v), want the 10.0.0 profile", got, ok)
	}

	if got, ok := Lookup(candidates[:1], "pkg:npm/dup@9.9.9", "9.9.9"); !ok || got.Version != "2.0.0" {
		t.Errorf("a single candidate must resolve regardless of version, got (%+v, %v)", got, ok)
	}
	if _, ok := Lookup(nil, "pkg:npm/x@1.0.0", "1.0.0"); ok {
		t.Error("no candidates must not resolve")
	}
}

// TestIndexDeduplicatesIdenticalPURLs: the same package@version approved by two
// projects is one profile, not an ambiguity.
func TestIndexDeduplicatesIdenticalPURLs(t *testing.T) {
	idx := Index(map[string]profile.Profile{
		"pkg:npm/same@1.0.0": prof("same", "1.0.0", "exec"),
	})
	if len(idx[Key("npm", "same")]) != 1 {
		t.Errorf("got %d profiles, want 1", len(idx[Key("npm", "same")]))
	}
	if amb := AmbiguousKeys(idx); len(amb) != 0 {
		t.Errorf("AmbiguousKeys = %v, want none", amb)
	}
}

func TestWriteSkipsZeroProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	if err := Write(path, "depsnort", time.Now(), []profile.Profile{{}, prof("real", "1.0.0")}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("loaded %d profiles, want 1 (the zero profile must be dropped)", len(got))
	}
}

// TestLookupPrefersExactIdentity guards the interaction D-42 introduced. Since
// a non-registry package carries its origin in its PURL, a baseline can hold a
// registry package and a git fork of it at the same name AND version —
// identical on every field except identity. Matching on version alone would
// compare the fork against the registry package's approved profile, which is
// exactly the cross-comparison DS-REV-03 exists to prevent.
func TestLookupPrefersExactIdentity(t *testing.T) {
	registry := prof("dup", "1.0.0")
	fork := prof("dup", "1.0.0", "network")
	fork.PURL = "pkg:npm/dup@1.0.0?source=git&source_ref=git%2Bhttps:%2F%2Fx.invalid%2Fr.git"
	fork.SourceClass = "git"
	candidates := []profile.Profile{registry, fork}

	got, ok := Lookup(candidates, fork.PURL, "1.0.0")
	if !ok {
		t.Fatal("the fork's own approved profile must resolve")
	}
	if got.PURL != fork.PURL || len(got.Caps) != 1 {
		t.Errorf("resolved to %+v, want the fork's profile", got)
	}

	got, ok = Lookup(candidates, registry.PURL, "1.0.0")
	if !ok || got.PURL != registry.PURL || len(got.Caps) != 0 {
		t.Errorf("resolved to %+v, want the registry profile", got)
	}

	// A third identity at the same version matches neither, and two candidates
	// share that version — so there is no answer, only a guess.
	if _, ok := Lookup(candidates, "pkg:npm/dup@1.0.0?source=path", "1.0.0"); ok {
		t.Error("an unknown identity colliding on version must not resolve")
	}
}
