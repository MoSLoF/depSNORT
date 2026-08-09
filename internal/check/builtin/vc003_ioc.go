package builtin

import (
	"fmt"
	"strings"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// IOCMatch (VC-003) flags a resolved package that appears in the operator's
// indicator-of-compromise ledger (Decision D-29). Unlike every other check in
// the pack, this is not a heuristic: the ledger is the operator's own confirmed
// intelligence, so a match is block-class with full confidence — the tool's job
// here is only to fan that one authoritative fact across the whole transitive
// tree, where a human would never catch it by eye.
//
// The ledger is supplied via -ioc and pre-matched onto ctx.IOC by the
// orchestrator. When no ledger is supplied, ctx.IOC is empty and this check is
// silent.
type IOCMatch struct{}

// Meta implements check.Check.
func (IOCMatch) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-003",
		Axis:            finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevCritical,
		DefaultGate:     finding.GateBlock,
		Description:     "package matches an entry in the operator's IOC ledger",
		DataDeps:        []string{"ioc"},
	}
}

// Run implements check.Check.
func (IOCMatch) Run(ctx *check.Context) []finding.Finding {
	if len(ctx.IOC) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		ind, ok := ctx.IOC[n.ID]
		if !ok {
			continue
		}

		var parts []string
		if ind.Category != "" {
			parts = append(parts, "category "+ind.Category)
		}
		if ind.Reference != "" {
			parts = append(parts, "ref "+ind.Reference)
		}
		if ind.Note != "" {
			parts = append(parts, ind.Note)
		}
		evidence := "listed in the operator IOC ledger"
		if len(parts) > 0 {
			evidence += " (" + strings.Join(parts, "; ") + ")"
		}

		out = append(out, finding.Finding{
			CheckID:     "VC-003",
			Axis:        finding.AxisKnownCompromise,
			Severity:    iocSeverity(ind.Severity),
			GateClass:   finding.GateBlock,
			Confidence:  1.0,
			NodeID:      n.ID,
			Title:       fmt.Sprintf("%s@%s is on the IOC ledger", n.Name, n.Version),
			Evidence:    evidence,
			Remediation: "do not install; this package is on your confirmed indicator ledger — treat as an active compromise",
		})
	}
	return out
}

// iocSeverity maps a ledger severity string to a finding severity. An IOC match
// always BLOCKS regardless of severity; this only affects finding ranking.
func iocSeverity(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return finding.SevLow
	case "medium":
		return finding.SevMedium
	case "high":
		return finding.SevHigh
	default:
		return finding.SevCritical
	}
}
