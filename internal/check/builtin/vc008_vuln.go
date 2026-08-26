package builtin

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/epss"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// KnownVuln (VC-008) reports ordinary disclosed vulnerabilities (CVE/GHSA) for
// a resolved package@version. It is table stakes, kept in its OWN axis and
// defaulted to ADVISORY gate-class so CVE noise never fails the build by
// default and never drowns the supply-chain signal (brief §5). Teams that want
// CVE gating opt in via policy later; that is a deliberate choice, not the
// default.
type KnownVuln struct{}

// Meta implements check.Check.
func (KnownVuln) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-008",
		Axis:            finding.AxisVuln,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "package@version has a disclosed vulnerability (OSV/GHSA CVE)",
		DataDeps:        []string{"osv"},
	}
}

// maxListedAdvisories caps how many advisory IDs are spelled out in the
// evidence string. The total is always reported, so the cap is disclosed rather
// than silent.
const maxListedAdvisories = 8

// Run implements check.Check.
//
// Findings are aggregated to ONE per package, not one per advisory. A live run
// against ten real outdated packages produced 66 separate VC-008 findings — 25
// on axios alone — which buried every supply-chain signal in the report. The
// gate was unaffected (advisories never gate), but a report nobody can read is
// its own kind of failure.
//
// When EPSS scores are present (ctx.EPSS, populated by -epss), each finding is
// annotated with the PEAK exploit-prediction score across its CVEs — carried as
// structured data (Finding.EPSS) as well as in the evidence prose — and the whole
// set is ordered by that peak, so the vulnerabilities most likely to be exploited
// in the wild surface first — the difference between "96 vulnerable packages" and
// "the 4 that matter this week".
//
// Gating posture: VC-008 is advisory by default (CVE noise never fails a build).
// When ctx.EPSSGate is set (-epss-gate) and a finding's peak EPSS is at or above
// it, that ONE finding is escalated to gate-eligible, so a team can opt into
// failing the build (-fail-on-eligible) on the handful of vulnerabilities that
// are actually being exploited while the rest stay advisory. The escalation is
// per-finding and still subject to presumed-version demotion in the verdict — a
// version this tool presumed rather than observed can never gate (D-44).
func (KnownVuln) Run(ctx *check.Context) []finding.Finding {
	type scored struct {
		f    finding.Finding
		peak float64
	}
	var ranked []scored
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		var ids []string
		var advs []datasource.Advisory
		for _, adv := range ctx.Advisories[n.ID] {
			if adv.Malicious {
				continue // that is VC-001's job
			}
			ids = append(ids, adv.ID)
			advs = append(advs, adv)
		}
		if len(ids) == 0 {
			continue
		}
		sort.Strings(ids)

		// The alias identities, deduped and excluding anything already listed as
		// an advisory id in its own right.
		primary := map[string]bool{}
		for _, id := range ids {
			primary[strings.ToUpper(id)] = true
		}
		aliasSet := map[string]bool{}
		for _, adv := range advs {
			for _, cve := range advisoryCVEs(adv) {
				if !primary[cve] {
					aliasSet[cve] = true
				}
			}
		}
		aliases := make([]string, 0, len(aliasSet))
		for a := range aliasSet {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)

		// Which IDs the prose cap KEEPS matters, because plain ID order is not
		// neutral: CVE ids sort chronologically, so an alphabetical cut showed
		// the eight OLDEST advisories and hid the newest, and hid every GHSA
		// outright once a package had eight or more CVEs (D-144). This file
		// already ranks findings so the vulnerabilities most likely to be
		// exploited surface first; the same signal now orders the ids INSIDE a
		// finding. Without EPSS there is no severity signal in an advisory
		// record, so sorted order stands as the deterministic fallback.
		listed := rankAdvisoryIDs(ids, advs, ctx.EPSS)
		suffix := ""
		if len(listed) > maxListedAdvisories {
			listed = listed[:maxListedAdvisories]
			suffix = fmt.Sprintf(", +%d more", len(ids)-maxListedAdvisories)
		}
		title := fmt.Sprintf("%d known %s", len(ids), plural(len(ids), "vulnerability", "vulnerabilities"))
		evidence := fmt.Sprintf("%s@%s is affected by %s%s", n.Name, n.Version, strings.Join(listed, ", "), suffix)

		sevPeak := peakSeverity(advs)

		peak := -1.0
		var es *finding.ExploitScore
		gate := finding.GateAdvisory
		if len(ctx.EPSS) > 0 {
			if score, ok := peakEPSS(advs, ctx.EPSS); ok {
				es = &score
				peak = score.Peak
				evidence += fmt.Sprintf("; peak EPSS %.3f (%s, %.0fth pct)", score.Peak, score.CVE, score.Percentile*100)
				if ctx.EPSSGate > 0 && score.Peak >= ctx.EPSSGate {
					gate = finding.GateEligible
					evidence += fmt.Sprintf("; gate-eligible (>= %.3f exploit-probability threshold)", ctx.EPSSGate)
				}
			}
		}

		ranked = append(ranked, scored{
			f: finding.Finding{
				CheckID:     "VC-008",
				Axis:        finding.AxisVuln,
				Severity:    finding.SevMedium,
				GateClass:   gate,
				Confidence:  1.0,
				NodeID:      n.ID,
				Title:       title,
				Evidence:    evidence,
				Remediation: "upgrade to a release that is not covered by these advisories",
				Advisories:  ids,
				Aliases:     aliases,
				Severity_:   sevPeak,
				EPSS:        es,
			},
			peak: peak,
		})
	}

	// Highest exploit-probability first when EPSS is present; SortedNodes order
	// (already deterministic) is preserved for ties and when EPSS is absent.
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].peak > ranked[j].peak })

	out := make([]finding.Finding, len(ranked))
	for i, r := range ranked {
		out[i] = r.f
	}
	return out
}

// rankAdvisoryIDs orders ids so the prose sample keeps the ones worth reading.
// ids carries the complete set either way and Finding.Advisories carries it
// into the report (D-144), so this decides presentation and never retention.
//
// Two signals, in order of how directly they speak to risk:
//
//  1. Exploit probability, when -epss supplied it. A measured prediction that
//     this vulnerability is being exploited beats any proxy.
//  2. Severity (D-147). How bad the vulnerability is if exploited, as the
//     advisory database published it. This is the signal D-145 recorded as
//     unavailable — true of querybatch, but /v1/query returns it and D-146
//     already made that call for the coordinates that matter.
//  3. Recency (D-145). A proxy, and the weakest of the three, but far better
//     than the sorted order it replaced: CVE identifiers sort chronologically,
//     so the old sample was reliably the OLDEST advisories a package had.
//
// The input must already be sorted: that order is the final tie-break, which is
// what keeps the output deterministic (D-09) when both signals are level.
func rankAdvisoryIDs(ids []string, advs []datasource.Advisory, scores map[string]epss.Score) []string {
	out := append([]string(nil), ids...)
	best := make(map[string]float64, len(advs))
	when := make(map[string]time.Time, len(advs))
	tier := make(map[string]int, len(advs))
	sev := make(map[string]float64, len(advs))
	for _, adv := range advs {
		when[adv.ID] = advisoryWhen(adv)
		tier[adv.ID] = severityTier(adv)
		if adv.ScoredSeverity {
			sev[adv.ID] = adv.Severity
		}
		for _, cve := range advisoryCVEs(adv) {
			if s, found := scores[cve]; found && s.EPSS > best[adv.ID] {
				best[adv.ID] = s.EPSS
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := best[out[i]], best[out[j]]; a != b {
			return a > b
		}
		if a, b := tier[out[i]], tier[out[j]]; a != b {
			return a > b
		}
		// Within a tier, an exact score refines the order where one is known.
		// Across tiers it must not: a scored 7.0 HIGH and a label-only CRITICAL
		// are not comparable as numbers, and the tier is the common currency
		// CVSS itself defines for them.
		if a, b := sev[out[i]], sev[out[j]]; a != b {
			return a > b
		}
		if a, b := when[out[i]], when[out[j]]; !a.Equal(b) {
			return a.After(b)
		}
		// Deliberately false rather than a comparison: SliceStable then leaves
		// the caller's sorted order intact. A non-strict comparator here would
		// break sort's contract and cost the determinism the tie-break exists
		// for — the mutation that proved this is recorded in D-144.
		return false
	})
	return out
}

// peakSeverity summarizes the worst severity among a package's advisories, by
// the same tier-then-score ordering the ranking uses, so the number shown is the
// one that did the work. nil when no advisory carried any severity at all.
func peakSeverity(advs []datasource.Advisory) *finding.AdvisorySeverity {
	var out *finding.AdvisorySeverity
	bestTier := 0
	for _, adv := range advs {
		t := severityTier(adv)
		if t == 0 {
			continue
		}
		if out != nil && (t < bestTier || (t == bestTier && adv.Severity <= out.Peak)) {
			continue
		}
		bestTier = t
		out = &finding.AdvisorySeverity{
			Peak:     adv.Severity,
			Scored:   adv.ScoredSeverity,
			Label:    adv.SeverityLabel,
			Advisory: adv.ID,
		}
	}
	return out
}

// severityTier maps an advisory onto CVSS's own published qualitative bands, so
// a scored vector and a bare database label can be compared at all. 0 means no
// severity signal of either kind.
//
// The bands are the specification's (§5): 0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9
// high, 9.0-10.0 critical. A scored 0.0 is NONE — a real rating meaning no
// impact — and ranks below every rated advisory but is still not "unknown".
func severityTier(adv datasource.Advisory) int {
	if adv.ScoredSeverity {
		switch {
		case adv.Severity >= 9.0:
			return 5
		case adv.Severity >= 7.0:
			return 4
		case adv.Severity >= 4.0:
			return 3
		case adv.Severity >= 0.1:
			return 2
		default:
			return 1 // scored NONE: rated, and rated harmless
		}
	}
	switch strings.ToUpper(adv.SeverityLabel) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM", "MODERATE":
		return 3
	case "LOW":
		return 2
	case "NONE":
		return 1
	}
	return 0 // no severity signal at all
}

// advisoryWhen estimates how recently an advisory changed, for ranking only.
//
// Modified is the real signal and is what OSV's querybatch actually returns.
// Records that reach the tool another way — an imported snapshot, the bundled
// dataset — carry no timestamp, so the year embedded in a CVE identifier
// stands in as a coarse fallback: it is a disclosure year rather than an update
// date, which is why it is consulted second and never allowed to overwrite a
// real one.
//
// A GHSA with neither a timestamp nor a CVE alias yields the zero time and
// falls to the sorted tie-break. That is the honest answer: its identifier
// encodes no date, and OSV's batch endpoint does not return the aliases that
// would supply one.
func advisoryWhen(adv datasource.Advisory) time.Time {
	if !adv.Modified.IsZero() {
		return adv.Modified
	}
	for _, id := range append([]string{adv.ID}, adv.Aliases...) {
		if y, ok := cveYear(id); ok {
			return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC)
		}
	}
	return time.Time{}
}

// cveYear pulls the year out of a CVE identifier ("CVE-2026-9002" -> 2026).
// The range guard keeps a malformed or hostile id from producing a year that
// would sort above every real advisory.
func cveYear(id string) (int, bool) {
	parts := strings.Split(strings.ToUpper(id), "-")
	if len(parts) < 3 || parts[0] != "CVE" {
		return 0, false
	}
	y, err := strconv.Atoi(parts[1])
	if err != nil || y < 1999 || y > 2200 {
		return 0, false
	}
	return y, true
}

// peakEPSS returns the peak exploit-prediction summary across an advisory set's
// CVEs (an advisory contributes its ID if it is a CVE, plus any CVE aliases).
// ok is false when none of the advisories has a scored CVE.
func peakEPSS(advs []datasource.Advisory, scores map[string]epss.Score) (finding.ExploitScore, bool) {
	var out finding.ExploitScore
	ok := false
	for _, adv := range advs {
		for _, cve := range advisoryCVEs(adv) {
			s, found := scores[cve]
			if !found {
				continue
			}
			if !ok || s.EPSS > out.Peak {
				ok = true
				out = finding.ExploitScore{Peak: s.EPSS, Percentile: s.Percentile, CVE: cve}
			}
		}
	}
	return out, ok
}

// advisoryCVEs returns the CVE IDs an advisory maps to: its own ID if it is a
// CVE, plus any CVE aliases.
func advisoryCVEs(adv datasource.Advisory) []string {
	var out []string
	if strings.HasPrefix(strings.ToUpper(adv.ID), "CVE-") {
		out = append(out, strings.ToUpper(adv.ID))
	}
	for _, a := range adv.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			out = append(out, strings.ToUpper(a))
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
