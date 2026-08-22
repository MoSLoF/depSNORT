package builtin

import (
	"fmt"
	"sort"
	"strings"

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

		listed := ids
		suffix := ""
		if len(listed) > maxListedAdvisories {
			listed = listed[:maxListedAdvisories]
			suffix = fmt.Sprintf(", +%d more", len(ids)-maxListedAdvisories)
		}
		title := fmt.Sprintf("%d known %s", len(ids), plural(len(ids), "vulnerability", "vulnerabilities"))
		evidence := fmt.Sprintf("%s@%s is affected by %s%s", n.Name, n.Version, strings.Join(listed, ", "), suffix)

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
