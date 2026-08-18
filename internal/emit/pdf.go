package emit

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// maxAdvisoryShown caps how many advisory findings are printed in full. Block
// and gate-eligible findings are never capped — those are the actionable ones.
const maxAdvisoryShown = 25

// maxRiskRowsShown caps the package-risk table. Clean packages are excluded
// entirely (they carry no information and dominate the count); this bounds the
// at-risk list itself.
const maxRiskRowsShown = 60

// maxCoverageNameChars caps the inline unresolved-name list per root. The
// complete list is always in the JSON.
const maxCoverageNameChars = 300

// PDF renders a human-readable scan report. It is the document format the iHBV
// conventions default to, and it is built on an in-tree writer so the tool keeps
// its zero-dependency footprint (Decision D-10).
type PDF struct{}

// Name implements Emitter.
func (PDF) Name() string { return "pdf" }

// gateColor maps a gate class to its accent colour.
func gateColor(g finding.GateClass) rgb {
	switch g {
	case finding.GateBlock:
		return colBlock
	case finding.GateEligible:
		return colGate
	default:
		return colAdvis
	}
}

// gateLabel is the human label for a gate class.
func gateLabel(g finding.GateClass) string {
	switch g {
	case finding.GateBlock:
		return "BLOCK"
	case finding.GateEligible:
		return "GATE-ELIGIBLE"
	default:
		return "ADVISORY"
	}
}

// verdictLine summarizes the run in one sentence.
//
// The degraded-coverage cases come BEFORE the clean cases (Decision D-24). A
// scan that resolved nothing has no business printing the word CLEAN: "we found
// nothing" and "we could not look" must never render the same way, because the
// first invites trust and only one of them has earned it.
// coverageReason renders the human-readable "why is this incomplete" phrase,
// folding every gap class the scan can carry — unresolved dependencies, orphans,
// failed workspace projects, partial install-surface extraction, and degraded
// data sources — so the banner never says "we could not look" without saying
// what it could not look at (finding F-02).
func coverageReason(cov graph.Coverage) string {
	var parts []string
	if cov.Unresolved > 0 {
		parts = append(parts, fmt.Sprintf("%d declared dependenc(ies) never resolved", cov.Unresolved))
	}
	if cov.Orphans > 0 {
		parts = append(parts, fmt.Sprintf("%d orphaned package(s)", cov.Orphans))
	}
	if cov.FailedProjects > 0 {
		parts = append(parts, fmt.Sprintf("%d project(s) failed to resolve", cov.FailedProjects))
	}
	if cov.ExtractorGaps > 0 {
		parts = append(parts, fmt.Sprintf("%d partial install-surface extraction(s)", cov.ExtractorGaps))
	}
	if cov.UnverifiableSources > 0 {
		parts = append(parts, fmt.Sprintf("%d package(s) from a non-registry source", cov.UnverifiableSources))
	}
	if len(cov.DataSourceGaps) > 0 {
		parts = append(parts, fmt.Sprintf("degraded data source(s): %s", strings.Join(cov.DataSourceGaps, ", ")))
	}
	if len(parts) == 0 {
		return "coverage is incomplete"
	}
	return strings.Join(parts, "; ")
}

func verdictLine(res verdict.Result) (string, rgb) {
	cov := res.Coverage
	switch {
	case res.Counts.Block > 0:
		return fmt.Sprintf("BLOCKED - %d block-class finding(s). Exit %d.",
			res.Counts.Block, res.ExitCode), colBlock
	case res.ExitCode == verdict.ExitGate:
		return fmt.Sprintf("GATED - %d gate-eligible finding(s) with policy opted in. Exit %d.",
			res.Counts.Eligible, res.ExitCode), colGate
	case cov.Incomplete() && res.Counts.Total == 0:
		return fmt.Sprintf(
			"INCOMPLETE - no findings, but %s. This is NOT an all-clear. Exit %d.",
			coverageReason(cov), res.ExitCode), colGate
	case cov.Incomplete():
		return fmt.Sprintf(
			"INCOMPLETE - %d finding(s), nothing block-class, but %s. Exit %d.",
			res.Counts.Total, coverageReason(cov), res.ExitCode), colGate
	case res.Counts.Total > 0:
		return fmt.Sprintf("PASSED with findings - nothing block-class. Exit %d.", res.ExitCode), colClean
	default:
		return fmt.Sprintf("CLEAN - no findings. Exit %d.", res.ExitCode), colClean
	}
}

// Emit implements Emitter.
func (PDF) Emit(w io.Writer, g *graph.Graph, res verdict.Result, info RunInfo) error {
	d := newPDFDoc()

	// ---- header -----------------------------------------------------------
	d.text("depSNORT", fontBold, 24, colInk, 0, 27)
	d.text("Dependency supply-chain scan report", fontRegular, 11, colMuted, 0, 15)
	d.text(fmt.Sprintf("%s  -  static, zero-execution analysis", Version),
		fontRegular, 8.5, colFaint, 0, 12)
	d.rule(colInk, 1.6, 6, 16)

	// ---- verdict banner ---------------------------------------------------
	line, col := verdictLine(res)
	d.space(30)
	// Panel first, then the accent bar, then the text on top of both. The box
	// bottom sits below the baseline so the text is vertically inside it.
	d.rectAt(marginLeft, contentW, 26, -8, colPanelBg)
	d.rectAt(marginLeft, 3.5, 26, -8, col)
	d.text(line, fontBold, 11.5, col, 12, 26)
	d.gap(8)

	// ---- scope ------------------------------------------------------------
	d.text("SCOPE", fontBold, 9, colFaint, 0, 14)
	roots := "(none)"
	if len(g.Roots) > 0 {
		roots = strings.Join(g.Roots, ", ")
	}
	d.wrapped("Root: "+roots, fontRegular, 9.5, colInk, 0, 12)
	kinds := g.CountByKind()
	d.text(fmt.Sprintf(
		"Graph: %d nodes (%d packages, %d install hooks, %d referenced artifacts, %d sinks), %d edges",
		g.Len(), kinds[graph.KindPackage], kinds[graph.KindInstallHook],
		kinds[graph.KindReferencedArtifact], kinds[graph.KindSink], len(g.Edges)),
		fontRegular, 9.5, colInk, 0, 12)
	d.text(fmt.Sprintf("Findings: %d block, %d gate-eligible, %d advisory (%d total)",
		res.Counts.Block, res.Counts.Eligible, res.Counts.Advisory, res.Counts.Total),
		fontRegular, 9.5, colInk, 0, 14)

	// ---- resolution coverage ----------------------------------------------
	// A first-class section, not a footnote (Decision D-24). What the scan could
	// not see bounds every conclusion drawn below it, so it is stated before the
	// findings rather than after them.
	cov := res.Coverage
	if !cov.Complete {
		d.gap(4)
		d.text("RESOLUTION COVERAGE", fontBold, 9, colFaint, 0, 14)
		if cov.Unresolved > 0 {
			d.wrapped(fmt.Sprintf(
				"%d declared dependenc(ies) across %d root(s) could not be resolved to a concrete "+
					"version and were NOT analyzed. No check ran against them. Every verdict in this "+
					"report is silent about them rather than clearing them.",
				cov.Unresolved, cov.IncompleteRoots), fontRegular, 8.5, colGate, 0, 11)
			for _, rc := range cov.Roots {
				if rc.Unresolved == 0 {
					continue
				}
				names := strings.Join(rc.Names, ", ")
				d.wrapped(fmt.Sprintf("  %s — %d unresolved: %s",
					rc.NodeID, rc.Unresolved, truncateRunes(names, maxCoverageNameChars)),
					fontMono, 7.5, colInk, 8, 10)
			}
		}
		if cov.Orphans > 0 {
			d.wrapped(fmt.Sprintf(
				"Resolver gap: %d package(s) are reachable from no root, meaning a dependency "+
					"relation was not parsed.", cov.Orphans), fontRegular, 8.5, colGate, 0, 11)
		}
		if len(cov.FlatEcosystems) > 0 {
			d.wrapped(fmt.Sprintf(
				"Flat resolution (%s): this lockfile format records no inter-package relationships, "+
					"so those packages resolve at depth 1 by construction, not by fact. Transitive "+
					"structure is unavailable for them and the depth column below should not be read "+
					"as a dependency tree.", strings.Join(cov.FlatEcosystems, ", ")),
				fontRegular, 8.5, colMuted, 0, 11)
		}
		if cov.FailedProjects > 0 {
			d.wrapped(fmt.Sprintf(
				"%d workspace project(s) failed to resolve; their dependency subtree is entirely "+
					"absent from this report, not cleared by it.", cov.FailedProjects),
				fontRegular, 8.5, colGate, 0, 11)
		}
		if cov.ExtractorGaps > 0 {
			d.wrapped(fmt.Sprintf(
				"%d install-surface extraction(s) were partial; the install-time subgraph for those "+
					"projects is a lower bound, so a hook that was not read is not the same as a hook "+
					"that is not there.", cov.ExtractorGaps), fontRegular, 8.5, colGate, 0, 11)
		}
		if cov.UnverifiableSources > 0 {
			d.wrapped(fmt.Sprintf(
				"%d package(s) resolved from a non-registry source (git, local path, or direct URL). "+
					"They have no registry coordinate, so the advisory pass over them could never have "+
					"returned a finding: that silence is missing coverage, not a clean result. %s",
				cov.UnverifiableSources,
				strings.Join(cov.UnverifiableSourceDetails, "; ")),
				fontRegular, 8.5, colGate, 0, 11)
		}
		if len(cov.DataSourceGaps) > 0 {
			d.wrapped(fmt.Sprintf(
				"Data source(s) degraded (%s): advisories or release history were unavailable for some "+
					"coordinates, so vulnerability and temporal checks are a lower bound over them.",
				strings.Join(cov.DataSourceGaps, ", ")), fontRegular, 8.5, colGate, 0, 11)
		}
		d.gap(2)
	}

	// ---- data source coverage --------------------------------------------
	if len(info.DataSources) > 0 {
		d.gap(4)
		d.text("DATA SOURCE COVERAGE", fontBold, 9, colFaint, 0, 14)
		for _, ds := range info.DataSources {
			s := ds.Stats
			mode := "online"
			if s.Offline {
				mode = "offline"
			}
			row := fmt.Sprintf("%-14s %s  -  queried %d, cache %d, network %d, advisories %d, gaps %d",
				ds.Name, mode, s.Queried, s.FromCache, s.FromNet, s.Advisories, s.Gaps)
			if s.NotFound > 0 {
				row += fmt.Sprintf(", not-published %d", s.NotFound)
			}
			d.text(row, fontMono, 8.5, colInk, 0, 11.5)
			if s.Gaps > 0 {
				d.wrapped(fmt.Sprintf(
					"Coverage is incomplete: %d coordinate(s) returned no data. Findings below are a lower bound.", s.Gaps),
					fontRegular, 8.5, colGate, 10, 11)
			}
			if ds.Error != "" {
				d.wrapped("Error: "+ds.Error, fontRegular, 8.5, colBlock, 10, 11)
			}
		}
	}

	// ---- findings ---------------------------------------------------------
	d.gap(8)
	d.rule(colRule, 0.8, 0, 12)
	d.text("FINDINGS", fontBold, 13, colInk, 0, 18)

	if len(res.Findings) == 0 {
		d.wrapped("No findings. Every resolved package was clean against the enabled checks and data sources.",
			fontRegular, 10, colMuted, 0, 13)
	} else {
		// Counts by check, so total volume is visible before the detail. A real
		// workspace produced 1,460 findings across 224 pages; a reader needs the
		// shape of that before wading into it.
		byCheck := map[string]int{}
		for _, f := range res.Findings {
			byCheck[f.CheckID]++
		}
		ids := make([]string, 0, len(byCheck))
		for id := range byCheck {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var parts []string
		for _, id := range ids {
			parts = append(parts, fmt.Sprintf("%s x%d", id, byCheck[id]))
		}
		d.wrapped("By check: "+strings.Join(parts, ",  "), fontMono, 8.5, colMuted, 0, 11)
		d.gap(4)
	}
	if len(res.Findings) > 0 {
		// Order: block first, then gate-eligible, then advisory; within a class
		// by descending score so the most actionable item is always on top.
		ordered := make([]finding.Finding, len(res.Findings))
		copy(ordered, res.Findings)
		rank := map[finding.GateClass]int{
			finding.GateBlock: 0, finding.GateEligible: 1, finding.GateAdvisory: 2,
		}
		sort.SliceStable(ordered, func(i, j int) bool {
			if rank[ordered[i].GateClass] != rank[ordered[j].GateClass] {
				return rank[ordered[i].GateClass] < rank[ordered[j].GateClass]
			}
			if ordered[i].Score() != ordered[j].Score() {
				return ordered[i].Score() > ordered[j].Score()
			}
			if ordered[i].CheckID != ordered[j].CheckID {
				return ordered[i].CheckID < ordered[j].CheckID
			}
			return ordered[i].NodeID < ordered[j].NodeID
		})

		lastClass := finding.GateClass("")
		shownInClass := 0
		omitted := map[finding.GateClass]int{}
		for _, f := range ordered {
			if f.GateClass != lastClass {
				lastClass = f.GateClass
				shownInClass = 0
				d.gap(6)
				d.text(gateLabel(f.GateClass), fontBold, 9.5, gateColor(f.GateClass), 0, 14)
			}
			// Every block and gate-eligible finding is shown — those are the
			// actionable ones. Advisory findings are capped: on a real workspace
			// they ran to 1,284 entries and 224 pages, which no one reads. The
			// remainder is DISCLOSED below and present in full in the JSON output,
			// because a silent cap is the failure this tool exists to avoid.
			if f.GateClass == finding.GateAdvisory && shownInClass >= maxAdvisoryShown {
				omitted[f.GateClass]++
				continue
			}
			shownInClass++
			d.space(46)
			c := gateColor(f.GateClass)

			// check id + subject
			subject := strings.TrimPrefix(f.NodeID, "pkg:")
			d.rect(marginLeft, 2.5, 11, c)
			d.text(fmt.Sprintf("%s  %s", f.CheckID,
				truncateToWidth(subject, 10, contentW-90)), fontBold, 10, colInk, 8, 13)

			// title
			d.wrapped(f.Title, fontRegular, 9.5, colInk, 8, 12)

			// scoring line
			score := f.Score()
			meta := fmt.Sprintf("severity %s  -  confidence %.2f", f.Severity, f.Confidence)
			if f.RecencyDecay > 0 {
				meta += fmt.Sprintf("  -  recency %.3f", f.RecencyDecay)
			}
			meta += fmt.Sprintf("  -  score %.3f", score)
			d.text(meta, fontMono, 8, colMuted, 8, 11)

			if f.Evidence != "" {
				d.wrapped("Evidence: "+f.Evidence, fontRegular, 8.5, colMuted, 8, 10.5)
			}
			if f.Remediation != "" {
				d.wrapped("Remediation: "+f.Remediation, fontRegular, 8.5, colMuted, 8, 10.5)
			}
			d.gap(5)
		}
		if n := omitted[finding.GateAdvisory]; n > 0 {
			d.gap(4)
			d.wrapped(fmt.Sprintf(
				"%d further advisory finding(s) are not listed here — only the %d highest-scoring are shown. "+
					"Advisory findings never affect the exit code; the complete set is in the JSON output "+
					"(-format json).", n, maxAdvisoryShown),
				fontRegular, 8.5, colGate, 0, 11)
		}
	}

	// ---- package risk table ----------------------------------------------
	d.gap(6)
	d.rule(colRule, 0.8, 0, 12)
	d.text("PACKAGE RISK", fontBold, 13, colInk, 0, 18)

	type row struct {
		name, version, risk string
		depth               int
		gateRank            int     // 0 block, 1 gate-eligible, 2 advisory-only
		score               float64 // highest composed score on the package
		truth               string  // version_truth, when not observed
	}
	var rows []row
	var clean int
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		// Clean packages are the overwhelming majority and carry no information
		// for a reader. A real workspace has 5,371 of them, which rendered ~80
		// pages of "CLEAN" rows. Only non-clean packages are listed; the clean
		// count is stated so nothing is hidden.
		if n.Risk == finding.RiskClean {
			clean++
			continue
		}
		r := row{name: n.Name, version: n.Version, risk: string(n.Risk), depth: n.Depth, gateRank: 2}
		if t := n.VersionTruth(); t != graph.TruthObserved {
			r.truth = t
		}
		for _, f := range n.Findings {
			switch f.GateClass {
			case finding.GateBlock:
				if r.gateRank > 0 {
					r.gateRank = 0
				}
			case finding.GateEligible:
				if r.gateRank > 1 {
					r.gateRank = 1
				}
			}
			if s := f.Score(); s > r.score {
				r.score = s
			}
		}
		rows = append(rows, r)
	}

	// Order by ACTIONABILITY, not by name (Decision D-22, corrected).
	//
	// The first cut of this table sorted alphabetically. With a 60-row cap on a
	// 394-row workspace that hid esbuild, sharp, bcrypt and ssh2 — every one of
	// them named in the findings section above — behind eighteen @types/d3-*
	// rows, purely because "e" sorts after "@t". A cap over an arbitrary order
	// is not a summary, it is a coin flip with a disclosure attached.
	riskRank := map[string]int{"flagged": 0, "warned": 1, "clean": 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].gateRank != rows[j].gateRank {
			return rows[i].gateRank < rows[j].gateRank
		}
		if riskRank[rows[i].risk] != riskRank[rows[j].risk] {
			return riskRank[rows[i].risk] < riskRank[rows[j].risk]
		}
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].name < rows[j].name
	})

	if len(rows) == 0 {
		d.wrapped(fmt.Sprintf("No package carries a risk state: all %d resolved packages are clean.", clean),
			fontRegular, 9.5, colMuted, 0, 13)
	} else {
		d.wrapped(fmt.Sprintf(
			"%d package(s) carry a risk state and are listed below. A further %d resolved package(s) "+
				"are clean and are not listed.", len(rows), clean),
			fontRegular, 8.5, colMuted, 0, 12)
		d.gap(3)

		// Header uses the SAME monospace font and format string as the rows —
		// a proportional header over monospace rows will not line up.
		const riskRowFmt = "%-9s %-34s %-14s %s"
		d.text(fmt.Sprintf(riskRowFmt, "RISK", "PACKAGE", "VERSION", "DEPTH"),
			fontMono, 8, colFaint, 8, 12)

		shown := 0
		anyPresumed := false
		for _, r := range rows {
			if shown >= maxRiskRowsShown {
				break
			}
			shown++
			c := colClean
			switch r.risk {
			case "flagged":
				c = colBlock
			case "warned":
				c = colGate
			}
			// A presumed or contested version is not a fact from a lockfile;
			// mark the version cell so the reader never mistakes a guessed
			// coordinate for an observed one (D-44).
			ver := r.version
			switch r.truth {
			case graph.TruthPresumed, graph.TruthAsserted:
				ver = "~" + ver
				anyPresumed = true
			case graph.TruthContested:
				ver = "?" + defaultIfEmpty(ver, "unresolved")
				anyPresumed = true
			}
			d.space(11)
			d.rect(marginLeft, 2.5, 9, c)
			d.text(fmt.Sprintf(riskRowFmt,
				strings.ToUpper(r.risk),
				truncateRunes(r.name, 34),
				truncateRunes(ver, 14),
				fmt.Sprintf("%d", r.depth)),
				fontMono, 8, colInk, 8, 11)
		}
		if anyPresumed {
			d.gap(3)
			d.wrapped(
				"A version marked \"~\" was PRESUMED by transitive expansion, not read "+
					"from a lockfile — the highest (or, for NuGet, lowest) published "+
					"version satisfying the declared range. A \"?\" marks a CONTESTED "+
					"version the declared ranges could not agree on. Findings on presumed "+
					"packages are advisory and never gate: the package is real, but this "+
					"exact version may not be in your build.",
				fontRegular, 8.5, colFaint, 8, 11)
		}
		if omitted := len(rows) - shown; omitted > 0 {
			d.gap(3)
			d.wrapped(fmt.Sprintf(
				"%d further at-risk package(s) are not listed here — only the %d most actionable "+
					"are shown, ordered by gate class then composed score. "+
					"The complete set is in the JSON output (-format json).", omitted, maxRiskRowsShown),
				fontRegular, 8.5, colGate, 8, 11)
		}
	}

	// ---- footer note ------------------------------------------------------
	d.gap(10)
	d.rule(colRule, 0.8, 0, 10)
	d.wrapped("depSNORT performs static analysis only: it parses manifests and lockfiles and never "+
		"runs a package manager or executes a lifecycle hook. It detects capability and indirection, not "+
		"payload semantics. Advisory findings never affect the exit code; gate-eligible findings do so "+
		"only when the run opts in; block findings always fail.",
		fontRegular, 7.5, colFaint, 0, 10)
	d.text("Report output is deterministic (no embedded timestamp).",
		fontRegular, 7.5, colFaint, 0, 10)

	_, err := w.Write(d.render("depSNORT scan report"))
	return err
}

// defaultIfEmpty returns fallback when s is empty. Used so a contested node with
// no version still renders a word rather than a bare "?".
func defaultIfEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
