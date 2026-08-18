// Package datasource is the layer between the resolved graph and the checks:
// it turns package coordinates into advisories (known-compromise + vuln facts)
// that checks then JUDGE (Decision D-03). Fetching is done here, once, in the
// scan orchestration — checks never reach the network themselves.
//
// Querying an advisory API is metadata I/O, not package execution, so it does
// not violate the zero-execution ethos (Decision D-04). Determinism and
// air-gap operation are preserved via the on-disk Cache and an offline mode.
package datasource

import (
	"context"
	"strings"
	"time"
)

// Coord is a package coordinate to look up.
type Coord struct {
	Ecosystem string // e.g. "npm"
	Name      string
	Version   string
}

// Key is the stable cache/identity key for a coordinate.
func (c Coord) Key() string {
	return c.Ecosystem + "|" + c.Name + "|" + c.Version
}

// Advisory is one advisory record about a specific package version.
type Advisory struct {
	ID        string    `json:"id"` // CVE-…, GHSA-…, MAL-…
	Summary   string    `json:"summary,omitempty"`
	Aliases   []string  `json:"aliases,omitempty"`
	Malicious bool      `json:"malicious"` // known-compromise (FLAG) vs ordinary vuln (WARN)
	Modified  time.Time `json:"modified,omitempty"`
	Source    string    `json:"source"` // e.g. "osv"
}

// ClassifyMalicious decides whether an advisory ID denotes a malicious-package
// advisory. OSV/GitHub publish these under the "MAL-" prefix. (GHSA-classified
// malware requires a details fetch to confirm; that hydration is a later
// refinement — v0 keys off the unambiguous prefix.)
func ClassifyMalicious(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "MAL-")
}

// Source is any advisory provider. The OSV client is the first implementation;
// Static (below) backs hermetic tests.
type Source interface {
	Name() string
	// QueryBatch returns advisories aligned by index to the input coords.
	QueryBatch(ctx context.Context, coords []Coord) ([][]Advisory, error)
}

// Stats summarizes a query pass, for coverage reporting (no silent caps).
type Stats struct {
	Queried    int  `json:"queried"`
	Advisories int  `json:"advisories"`
	Malicious  int  `json:"malicious"`
	FromCache  int  `json:"from_cache"`
	FromNet    int  `json:"from_network"`
	Offline    bool `json:"offline"`
	Gaps       int  `json:"gaps"` // coords with no data (offline miss / error)
	// NotFound counts coordinates the source has no record of at all — a 404.
	// Tracked separately from Gaps because it is a different fact: "this package
	// is not published here" (normal for private, internal, or unpublished
	// packages) rather than "the lookup failed". Conflating them makes an
	// ordinary private dependency look like a broken scan.
	NotFound int `json:"not_found,omitempty"`
	// UnparsedEntries counts individual dependency specifiers inside a
	// SUCCESSFULLY fetched response that could not be parsed at all. Tracked
	// separately from Gaps for the same reason NotFound is: it is a different
	// fact. The coordinate's metadata was retrieved fine — part of its content
	// was unreadable — so any dependency edge that entry would have produced is
	// missing. Folding it into Gaps would make a partially-unreadable response
	// indistinguishable from a failed lookup, and leaving it uncounted would let
	// a dropped dependency pass as a clean result (Decision D-24).
	UnparsedEntries int `json:"unparsed_entries,omitempty"`
	// FromBundled counts coordinates served from a compiled-in fallback
	// dataset AS MALICIOUS-PACKAGE COVERAGE — consulted only when neither the
	// cache nor a live query had an answer. Tracked separately from
	// FromCache/FromNet so a bundled-sourced finding is never mistaken for a
	// live or freshly-cached one.
	//
	// Only entries carrying at least one malicious-package advisory count here
	// (finding DS-REV-01). The tier is documented as the offline substitute for
	// a live VC-001 check, so an entry holding only ordinary CVEs has not
	// answered that question and must not read as though it had.
	FromBundled int `json:"from_bundled,omitempty"`
	// BundledNonMalicious counts coordinates the fallback dataset DID hold, but
	// with no malicious-package advisory. Their CVE context is still returned
	// and reported; they simply also count as a gap, because nothing checked
	// them for malware. Tracked separately from Gaps so a report can say which
	// of the two happened rather than merging "not in the dataset" with "in the
	// dataset, but not as malware coverage".
	BundledNonMalicious int `json:"bundled_non_malicious,omitempty"`
	// BundledDatasetAt is when the compiled-in fallback dataset was
	// generated. Present whenever the dataset was consulted successfully, so a
	// report can disclose exactly how stale a bundled-sourced answer might be
	// rather than letting it read as equivalent to a live check (Decision
	// D-24).
	BundledDatasetAt *time.Time `json:"bundled_dataset_generated_at,omitempty"`
}

// RegistrySource provides release-history metadata for a single ecosystem. The
// npm registry client was the first implementation; RubyGems, Cargo, Composer,
// and NuGet follow the same contract.
type RegistrySource interface {
	Name() string
	Ecosystem() string
	Histories(ctx context.Context, names []string) (map[string]*ReleaseHistory, error)
	GetStats() Stats
}

// Static is a map-backed Source for tests and offline fixtures.
type Static struct {
	M map[string][]Advisory // keyed by Coord.Key()
}

// Name implements Source.
func (Static) Name() string { return "static" }

// QueryBatch implements Source.
func (s Static) QueryBatch(_ context.Context, coords []Coord) ([][]Advisory, error) {
	out := make([][]Advisory, len(coords))
	for i, c := range coords {
		out[i] = s.M[c.Key()]
	}
	return out, nil
}
