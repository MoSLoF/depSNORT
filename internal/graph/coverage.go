package graph

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Resolution-coverage facts (Decision D-24).
//
// These keys are ECOSYSTEM-NEUTRAL on purpose. Coverage is a property of the
// scan, not of npm or PyPI, and the verdict layer must be able to read it
// without knowing which adapter produced the graph. An adapter records what it
// could not see; it never decides what that means. (Extraction vs judgment,
// Decision D-03.)
const (
	// AttrUnresolved is a comma-separated list of dependency names that were
	// declared but could not be resolved to a concrete version.
	AttrUnresolved = "depsnort.unresolved"
	// AttrUnresolvedCount is len(AttrUnresolved), stored separately so readers
	// never have to parse the list to get a count.
	AttrUnresolvedCount = "depsnort.unresolved_count"
	// AttrFlatResolution marks a root whose lockfile format records no
	// inter-package relationships, so the tree beneath it is one layer deep by
	// construction rather than by fact. The value is the ecosystem name.
	AttrFlatResolution = "depsnort.flat_resolution"
)

// RootCoverage is what one root could not resolve.
type RootCoverage struct {
	NodeID     string   `json:"node_id"`
	Unresolved int      `json:"unresolved,omitempty"`
	Names      []string `json:"unresolved_names,omitempty"`
	Flat       string   `json:"flat_resolution,omitempty"`
}

// Coverage answers "how much of the declared tree did we actually see?".
//
// This is deliberately separate from risk. A scan can be entirely clean and
// entirely uninformative at the same time, and conflating the two produces the
// most dangerous output a detection tool can emit: a confident all-clear over
// something it never read.
type Coverage struct {
	// Complete is true only when nothing was left unresolved, no root resolved
	// flat, and no package is orphaned.
	Complete bool `json:"complete"`
	// Degraded is the narrower and more serious claim: the resolver failed to
	// see something it should have seen — an unpinned dependency, or a package
	// reachable from no root.
	//
	// Kept distinct from Complete because a flat lockfile format is a
	// LIMITATION OF THE FORMAT, not a failure of the scan. Pipfile.lock records
	// no inter-package relationships; reporting that as a resolver defect on
	// every Python project would be exactly the warning tax that gets a tool
	// muted. Degraded is what gates; Complete is what gets disclosed.
	Degraded bool `json:"degraded"`
	// Unresolved is the total count of declared-but-unpinned dependencies.
	Unresolved int `json:"unresolved_dependencies"`
	// IncompleteRoots is how many roots contributed at least one of those.
	IncompleteRoots int `json:"incomplete_roots"`
	// FlatEcosystems lists ecosystems whose lockfile format cannot express
	// transitive structure in this scan.
	FlatEcosystems []string `json:"flat_resolution_ecosystems,omitempty"`
	// Orphans is the count of packages reachable from no root (Decision D-18).
	Orphans int `json:"orphans"`
	// Roots carries the per-root detail, sorted by node ID for determinism.
	Roots []RootCoverage `json:"roots,omitempty"`

	// --- Scan-level gaps (Decision D-32 / finding F-02) --------------------
	// These are NOT derivable from the graph alone: they come from stages the
	// graph never sees — data-source lookups, install-surface extraction, and
	// multi-project workspace resolution. The CLI populates them AFTER those
	// stages and before calling the verdict. Before they existed, only the
	// graph-level Degraded flag above could reach the exit code, so an empty
	// OSV cache, a failed registry source, an unreadable install surface, or a
	// workspace project that never resolved could all still return a clean 0
	// under -fail-on-incomplete. Incomplete() folds them in.

	// DataSourceGaps names the data sources (OSV, per-ecosystem registries)
	// that errored or returned no data for coordinates that were queried.
	DataSourceGaps []string `json:"data_source_gaps,omitempty"`
	// ExtractorGaps counts install-surface material that was NOT examined for a
	// resolved project (the install-time subgraph for it is a lower bound).
	ExtractorGaps int `json:"install_surface_gaps,omitempty"`
	// ExtractorGapReasons summarizes those gaps by reason, e.g.
	// "containment-refusal x3". A containment refusal is not just a gap, it is
	// an ACTIVE signal — an ordinary package does not symlink its manifest out
	// of the tree — so the reason has to survive into the report rather than
	// being flattened into a count (finding R-01).
	ExtractorGapReasons []string `json:"install_surface_gap_reasons,omitempty"`
	// ExtractorGapDetails is a bounded sample of individual gaps, for the human
	// report. Capped so a tree with thousands of planted symlinks does not
	// produce a thousand-line report; the count above is never capped.
	ExtractorGapDetails []string `json:"install_surface_gap_details,omitempty"`
	// FailedProjects counts workspace projects (under -recursive) that did not
	// resolve at all, so their whole subtree is missing from the graph.
	FailedProjects int `json:"failed_projects,omitempty"`

	// UnverifiableSources counts resolved packages whose origin is not a
	// registry — git URLs, local paths, direct artifact URLs (Decision D-41).
	// These packages have no coordinate an advisory feed indexes, so the OSV
	// pass over them returned nothing it could ever have returned anything
	// else for. Counting that as coverage rather than cleanliness is the same
	// invariant as the rest of this struct, applied to provenance.
	UnverifiableSources int `json:"unverifiable_sources,omitempty"`
	// UnverifiableSourceDetails is a bounded sample naming what could not be
	// verified ("pkg:cargo/vt100-psmux@0.16.9 [path]"). Capped like
	// ExtractorGapDetails so a heavily vendored tree does not produce a
	// thousand-line report; the count above is never capped.
	UnverifiableSourceDetails []string `json:"unverifiable_source_details,omitempty"`
}

// maxUnverifiableDetails bounds the sample above. Chosen to match the
// install-surface gap sample: enough to characterize the shape of the problem,
// not enough to become the report.
const maxUnverifiableDetails = 10

// Incomplete reports whether coverage is degraded for ANY reason — graph
// resolution OR a scan-level gap. This is the single fact the verdict gates on
// under -fail-on-incomplete (finding F-02). Keeping the graph-only Degraded flag
// distinct preserves its specific meaning for reporting ("N unresolved
// dependencies across M roots"), while Incomplete() is the honest answer to the
// only question a gate actually asks: "is this an all-clear, or could we not
// look?".
func (c Coverage) Incomplete() bool {
	return c.Degraded ||
		len(c.DataSourceGaps) > 0 ||
		c.ExtractorGaps > 0 ||
		c.FailedProjects > 0 ||
		c.UnverifiableSources > 0
}

// IncompleteSummary renders "coverage is incomplete" as one sentence, shared
// verbatim between the CLI's stderr warning and SARIF's execution
// notification so the two surfaces never describe the same fact differently.
func (c Coverage) IncompleteSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"coverage is incomplete: %d unresolved dependenc(ies) across %d root(s), "+
			"%d orphaned package(s), %d failed project(s), %d partial install-surface extraction(s)",
		c.Unresolved, c.IncompleteRoots, c.Orphans, c.FailedProjects, c.ExtractorGaps)
	if len(c.ExtractorGapReasons) > 0 {
		fmt.Fprintf(&b, " [%s]", strings.Join(c.ExtractorGapReasons, ", "))
	}
	if c.UnverifiableSources > 0 {
		fmt.Fprintf(&b, ", %d package(s) from a non-registry source (no advisory coverage)",
			c.UnverifiableSources)
		if len(c.UnverifiableSourceDetails) > 0 {
			fmt.Fprintf(&b, " [%s]", strings.Join(c.UnverifiableSourceDetails, ", "))
		}
	}
	if len(c.DataSourceGaps) > 0 {
		fmt.Fprintf(&b, ", degraded data source(s): %s", strings.Join(c.DataSourceGaps, ", "))
	}
	b.WriteString(". This report is NOT an all-clear.")
	return b.String()
}

// Coverage computes the resolution-coverage facts recorded on the graph.
func (g *Graph) Coverage() Coverage {
	cov := Coverage{Orphans: len(g.Orphans())}
	flat := map[string]bool{}

	isRoot := make(map[string]bool, len(g.Roots))
	for _, r := range g.Roots {
		isRoot[r] = true
	}

	for _, n := range g.SortedNodes() {
		if len(n.Attr) == 0 {
			continue
		}
		// Provenance (D-41). Roots are excluded: the project being scanned is
		// not a dependency of itself, and a checkout is a local path by
		// definition — charging the scan for that would flag every scan of
		// every workspace.
		if n.Kind == KindPackage && !isRoot[n.ID] {
			if class := n.Attr[AttrSourceClass]; class != "" && !Verifiable(class) {
				cov.UnverifiableSources++
				if len(cov.UnverifiableSourceDetails) < maxUnverifiableDetails {
					cov.UnverifiableSourceDetails = append(cov.UnverifiableSourceDetails,
						fmt.Sprintf("%s [%s]", n.ID, class))
				}
			}
		}
		rc := RootCoverage{NodeID: n.ID}
		if raw := n.Attr[AttrUnresolvedCount]; raw != "" {
			if c, err := strconv.Atoi(raw); err == nil && c > 0 {
				rc.Unresolved = c
				cov.Unresolved += c
				cov.IncompleteRoots++
			}
		}
		if names := n.Attr[AttrUnresolved]; names != "" {
			rc.Names = strings.Split(names, ",")
		}
		if eco := n.Attr[AttrFlatResolution]; eco != "" {
			rc.Flat = eco
			flat[eco] = true
		}
		if rc.Unresolved > 0 || rc.Flat != "" {
			cov.Roots = append(cov.Roots, rc)
		}
	}

	for eco := range flat {
		cov.FlatEcosystems = append(cov.FlatEcosystems, eco)
	}
	sort.Strings(cov.FlatEcosystems) // determinism (D-13)

	cov.Degraded = cov.Unresolved > 0 || cov.Orphans > 0
	cov.Complete = !cov.Incomplete() && len(cov.FlatEcosystems) == 0
	return cov
}
