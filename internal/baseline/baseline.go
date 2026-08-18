// Package baseline reads and writes the operator-promoted known-good record a
// drift scan compares against.
//
// A baseline is deliberately a FILE, not an inferred "last good version"
// (Decision D-40). Inferring the baseline from a registry would mean trusting
// whatever the registry served most recently — which is exactly the thing under
// suspicion when a maintainer account is compromised, and would also make the
// drift verdict depend on network state rather than on something an operator
// reviewed. A committed file is reviewable, diffable, signable, and identical
// on every runner including air-gapped ones.
//
// The format is plain JSON, sorted and indented, for the same reason the OSV
// snapshot format is: it is meant to be read in a pull request, not just parsed.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"ihbv.io/depsnort/internal/profile"
)

// Schema is the baseline file format version. A file written under a different
// schema is REFUSED rather than partially understood: a baseline is a security
// control, and silently comparing against a record whose fields have moved is
// worse than having no baseline at all.
const Schema = "depsnort.baseline/1"

// maxBaselineBytes bounds a baseline read. A large monorepo baseline runs to a
// few megabytes; the cap is headroom against a malformed or hostile file, in
// the same spirit as the OSV snapshot limit.
const maxBaselineBytes = 64 << 20

// File is the on-disk baseline document.
type File struct {
	Schema string `json:"schema"`
	Tool   string `json:"tool"`
	// Created is stamped for human context only. Nothing reads it back: a
	// baseline's authority comes from an operator having committed it, not from
	// its age.
	Created string `json:"created,omitempty"`
	// Profiles are sorted by PURL so the file is byte-stable across runs and
	// diffs cleanly in review.
	Profiles []profile.Profile `json:"profiles"`
}

// Write serializes profiles to path. The profile list is sorted and the
// timestamp is confined to the Created field, so writing the same scan twice
// produces identical bytes apart from that one line — the property that lets a
// baseline be committed without generating churn.
func Write(path, tool string, created time.Time, profiles []profile.Profile) error {
	sorted := make([]profile.Profile, 0, len(profiles))
	for _, p := range profiles {
		if p.IsZero() {
			continue
		}
		sorted = append(sorted, p)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PURL < sorted[j].PURL })

	f := File{
		Schema:   Schema,
		Tool:     tool,
		Created:  created.UTC().Format(time.RFC3339),
		Profiles: sorted,
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: writing %s: %w", path, err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("baseline: writing %s: %w", path, err)
	}
	return nil
}

// Load reads a baseline and returns its profiles keyed by PURL.
//
// A file whose schema this build does not recognize is an error, never a
// silently empty baseline: an operator who passed -baseline asked for drift to
// be evaluated, and a scan that quietly evaluates nothing while exiting 0 is
// the failure mode this whole package exists to avoid.
func Load(path string) (map[string]profile.Profile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("baseline: %s: not a regular file", path)
	}
	if info.Size() > maxBaselineBytes {
		return nil, fmt.Errorf("baseline: %s: %d bytes exceeds %d byte limit",
			path, info.Size(), maxBaselineBytes)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("baseline: %s: %w", path, err)
	}
	if f.Schema != Schema {
		return nil, fmt.Errorf("baseline: %s: schema %q is not %q — regenerate it with this build",
			path, f.Schema, Schema)
	}

	out := make(map[string]profile.Profile, len(f.Profiles))
	for _, p := range f.Profiles {
		if p.IsZero() {
			continue
		}
		out[p.PURL] = p
	}
	return out, nil
}

// Key is the identity a candidate package is looked up by. A baseline records
// the version it was promoted at, so lookup deliberately ignores version: the
// question is "what did this package look like when we approved it", and the
// candidate's version is by definition different when there is drift to find.
func Key(ecosystem, name string) string { return ecosystem + "|" + name }

// Index groups profiles by ecosystem+name for candidate lookup, keeping EVERY
// approved version under its key (finding DS-REV-03).
//
// The previous implementation returned one profile per key and let the highest
// sorted PURL win, which it described as deterministic. It was — and it was
// also wrong twice over. PURL order is lexicographic, so a baseline holding
// 2.0.0 and 10.0.0 selected 2.0.0; and even a correct semantic ordering picks
// the wrong answer when two projects in one workspace have legitimately
// approved different versions, because the right profile is a question about
// WHICH PROJECT the candidate came from, not about which version is newest.
// Comparing a candidate against another project's baseline generates false
// drift and hides real drift with equal confidence.
//
// So nothing is discarded here. Deciding what a set of several approved
// versions means is the caller's job, and VC-010 refuses to conclude rather
// than guess.
//
// Profiles are deduplicated by PURL — the same package@version approved by two
// projects is one profile, not an ambiguity — and sorted, so the result is
// stable across runs.
func Index(profiles map[string]profile.Profile) map[string][]profile.Profile {
	purls := make([]string, 0, len(profiles))
	for purl := range profiles {
		purls = append(purls, purl)
	}
	sort.Strings(purls)

	out := make(map[string][]profile.Profile, len(profiles))
	seen := map[string]bool{}
	for _, purl := range purls {
		if seen[purl] {
			continue
		}
		seen[purl] = true
		p := profiles[purl]
		k := Key(p.Ecosystem, p.Name)
		out[k] = append(out[k], p)
	}
	return out
}

// Lookup resolves the baseline profile a candidate version should be compared
// against.
//
// The three outcomes are deliberately distinct, because collapsing any two of
// them is how a drift axis starts lying:
//
//   - (profile, true): exactly one approved version, or an exact match on the
//     candidate's own version. An exact match means this version IS approved,
//     so there is nothing to compare and no drift by construction.
//   - (zero, false) with no candidates: the package is new to this tree, not
//     drifted.
//   - (zero, false) with several candidates: ambiguous. The caller must
//     disclose it and draw no conclusion.
//
// Callers distinguish the last two by the length of the slice they passed.
//
// purl is the candidate's full identity and is tried FIRST. Since D-42 a
// non-registry package carries its origin in its PURL, so a baseline can hold a
// registry package and a git fork of it at the same name AND the same version —
// identical on every field this function would otherwise compare. Only the PURL
// separates them, and comparing a fork against the registry package's approved
// profile is precisely the cross-comparison DS-REV-03 exists to prevent.
func Lookup(candidates []profile.Profile, purl, version string) (profile.Profile, bool) {
	if len(candidates) == 0 {
		return profile.Profile{}, false
	}
	// Exact identity: this artifact is approved, whatever else shares its name.
	for _, c := range candidates {
		if c.PURL == purl {
			return c, true
		}
	}
	if len(candidates) == 1 {
		return candidates[0], true
	}
	// Same version but a different identity is NOT a match: with several
	// candidates, a version collision means two different artifacts, and
	// picking either would be the guess this function refuses to make.
	var match profile.Profile
	found := 0
	for _, c := range candidates {
		if c.Version == version {
			match = c
			found++
		}
	}
	if found == 1 {
		return match, true
	}
	return profile.Profile{}, false
}

// Versions lists the approved versions under one key, for a diagnostic that
// names what it could not choose between.
func Versions(candidates []profile.Profile) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.Version)
	}
	sort.Strings(out)
	return out
}

// AmbiguousKeys lists the baseline keys holding more than one approved version,
// sorted. Used to disclose up front that drift will be skipped for them rather
// than leaving the omission to be inferred from an absent finding.
func AmbiguousKeys(index map[string][]profile.Profile) []string {
	var out []string
	for k, candidates := range index {
		if len(candidates) > 1 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
