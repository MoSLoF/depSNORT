package builtin

import (
	"fmt"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// MaliciousVersion (VC-001) is the deterministic FLAG: this exact
// package@version appears in a known-malicious advisory (OSV/GHSA "MAL-*").
// It is the block-worthy, "this release is poisoned" case — always gates.
type MaliciousVersion struct{}

// Meta implements check.Check.
func (MaliciousVersion) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-001",
		Axis:            finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevCritical,
		DefaultGate:     finding.GateBlock,
		Description:     "package@version is in a known-malicious advisory (OSV/GHSA MAL-*)",
		DataDeps:        []string{"osv"},
	}
}

// Run implements check.Check.
func (MaliciousVersion) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		for _, adv := range ctx.Advisories[n.ID] {
			if !adv.Malicious {
				continue
			}
			out = append(out, finding.Finding{
				CheckID:     "VC-001",
				Axis:        finding.AxisKnownCompromise,
				Severity:    finding.SevCritical,
				GateClass:   finding.GateBlock,
				Confidence:  1.0,
				NodeID:      n.ID,
				Title:       fmt.Sprintf("known-malicious release (%s)", adv.ID),
				Evidence:    fmt.Sprintf("%s@%s matches malicious advisory %s", n.Name, n.Version, adv.ID),
				Remediation: "do not install; remove or pin away from this version and rotate any exposed credentials",
			})
		}
	}
	return out
}
