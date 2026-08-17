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

func TestIndexIsDeterministicAcrossDuplicateNames(t *testing.T) {
	profiles := map[string]profile.Profile{
		"pkg:npm/dup@1.0.0": prof("dup", "1.0.0", "exec"),
		"pkg:npm/dup@2.0.0": prof("dup", "2.0.0", "network"),
	}
	first := Index(profiles)[Key("npm", "dup")]
	for range 20 {
		if got := Index(profiles)[Key("npm", "dup")]; got.Version != first.Version {
			t.Fatalf("Index picked %s then %s; duplicate names must resolve deterministically",
				first.Version, got.Version)
		}
	}
	if first.Version != "2.0.0" {
		t.Errorf("Index kept %s, want the highest PURL (2.0.0)", first.Version)
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
