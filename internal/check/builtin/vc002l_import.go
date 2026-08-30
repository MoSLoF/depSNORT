package builtin

import (
	"fmt"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// HookImportTime (VC-002L) reports a Python package module whose top-level code
// runs a suspicious capability at IMPORT time — an ordinary runtime module (not
// an install hook) that executes on `import`, the vector behind the telnyx
// _client.py compromise. See docs/VC-002L-python-import-time.md and Decision
// D-165.
//
// The import-time surface is broad and overwhelmingly benign, so this is
// ADVISORY ONLY and never gates. The layering that enforces that: the analyzer
// (installsurface.AnalyzePythonLoadTime) already applied the escalating-capability
// gate before a hook exists; the block-class VC-002 family excludes these
// "import-time:" hooks (collectHooks); and this check caps them at advisory. A
// finding here says "worth a human's eye before install," not "blocked."
type HookImportTime struct{}

// Meta implements check.Check.
func (HookImportTime) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-002L",
		Axis:            finding.AxisKnownCompromise,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "package module runs a suspicious capability at import time (advisory)",
	}
}

// Run implements check.Check.
func (HookImportTime) Run(ctx *check.Context) []finding.Finding {
	var out []finding.Finding
	for _, hook := range ctx.Graph.SortedNodes() {
		if hook.Kind != graph.KindInstallHook || !strings.HasPrefix(hook.Name, "import-time:") {
			continue
		}
		caps := importTimeCaps(hook)
		if len(caps) == 0 {
			continue
		}
		module := strings.TrimPrefix(hook.Name, "import-time:")

		subject := hook.Attr["hook.package"]
		if pkg := ctx.Graph.Get(subject); pkg != nil {
			subject = pkg.Name + "@" + pkg.Version
		}

		out = append(out, finding.Finding{
			CheckID:     "VC-002L",
			Axis:        finding.AxisKnownCompromise,
			Severity:    finding.SevMedium,
			GateClass:   finding.GateAdvisory,
			Confidence:  0.4,
			NodeID:      hook.ID,
			Title:       fmt.Sprintf("%s runs code at import: %s", subject, module),
			Evidence:    fmt.Sprintf("%s executes on import with capabilities %s (runtime module, not an install hook)", module, strings.Join(caps, "+")),
			Remediation: "review the module's top-level code before installing; a runtime module that reads credentials or decodes-and-executes on import is not normal library behavior",
		})
	}
	return out
}

// importTimeCaps returns the sorted capability names attached to an import-time
// hook node.
func importTimeCaps(n *graph.Node) []string {
	var caps []string
	for k, v := range n.Attr {
		if v == "true" && strings.HasPrefix(k, "cap.") {
			caps = append(caps, strings.TrimPrefix(k, "cap."))
		}
	}
	sort.Strings(caps)
	return caps
}
