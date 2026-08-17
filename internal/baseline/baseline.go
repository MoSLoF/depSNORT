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

// Index rekeys profiles by ecosystem+name for candidate lookup. Where a
// baseline holds several versions of the same package — legal in a workspace
// where two projects pin differently — the highest PURL wins deterministically
// rather than whichever map iteration reached last.
func Index(profiles map[string]profile.Profile) map[string]profile.Profile {
	purls := make([]string, 0, len(profiles))
	for purl := range profiles {
		purls = append(purls, purl)
	}
	sort.Strings(purls)

	out := make(map[string]profile.Profile, len(profiles))
	for _, purl := range purls {
		p := profiles[purl]
		out[Key(p.Ecosystem, p.Name)] = p
	}
	return out
}
