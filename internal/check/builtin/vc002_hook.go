// Package builtin holds the v0 vector-check pack. Each file is one check (or
// one family). They are the FIRST plugin pack, not a privileged core — they
// implement the same check.Check contract a third-party plugin will.
package builtin

import (
	"fmt"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// HookPresent (VC-002a) is the seed of the ChainDrop-class detector. In v0 it
// only fires on the FACT an adapter can already surface statically: a package
// that declares an install lifecycle hook (npm's hasInstallScript).
//
// It is deliberately WARN / gate-eligible and LOW severity in isolation — a
// lone hook is common and mostly benign (brief §6). The dangerous, higher-
// confidence signal is a hook whose install-time subgraph reaches off-tree
// (network/creds/C2); scoring that requires install-surface extraction
// (step 5), at which point this grows into the full VC-002 family.
type HookPresent struct{}

// Meta implements check.Check.
func (HookPresent) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-002a",
		Axis:            finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevLow,
		DefaultGate:     finding.GateEligible,
		Description:     "package declares an install lifecycle hook (preinstall/install/postinstall)",
	}
}

// Run implements check.Check.
func (HookPresent) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		if n.Attr["npm.hasInstallScript"] != "true" {
			continue
		}
		out = append(out, finding.Finding{
			CheckID:     "VC-002a",
			Axis:        finding.AxisKnownCompromise,
			Severity:    finding.SevLow,
			GateClass:   finding.GateEligible,
			Confidence:  0.35, // low on its own; a multiplier, not an alarm
			NodeID:      n.ID,
			Title:       "declares an install lifecycle hook",
			Evidence:    fmt.Sprintf("%s@%s has hasInstallScript=true in the lockfile", n.Name, n.Version),
			Remediation: "review the package's install scripts before installing; confirm the hook is expected for a native build",
		})
	}
	return out
}
