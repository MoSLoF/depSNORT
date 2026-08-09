package builtin

import (
	"fmt"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/check"
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
func (KnownVuln) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		var ids []string
		for _, adv := range ctx.Advisories[n.ID] {
			if adv.Malicious {
				continue // that is VC-001's job
			}
			ids = append(ids, adv.ID)
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
		out = append(out, finding.Finding{
			CheckID:     "VC-008",
			Axis:        finding.AxisVuln,
			Severity:    finding.SevMedium,
			GateClass:   finding.GateAdvisory,
			Confidence:  1.0,
			NodeID:      n.ID,
			Title:       title,
			Evidence:    fmt.Sprintf("%s@%s is affected by %s%s", n.Name, n.Version, strings.Join(listed, ", "), suffix),
			Remediation: "upgrade to a release that is not covered by these advisories",
		})
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
