package builtin

import (
	"fmt"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// UnverifiableSource (VC-009) reports a dependency that did not come from a
// package registry — a git URL, a local path, or a direct artifact URL
// (Decision D-41).
//
// # Why this is advisory on its own
//
// Vendoring is not a smell. A field review of a Rust project found two forked
// crates vendored in-tree as path dependencies and concluded, correctly, that
// this was a STRONGER posture than git dependencies would have been: the code
// is pinned, in-repo, reviewable in the same pull request as everything else,
// and immune to an upstream force-push swapping it underneath a build. Flagging
// that as a risk would be wrong, and flagging it loudly would teach operators
// to mute the check.
//
// What is true regardless of posture is that the advisory pass could not speak
// to those packages at all. They have no registry coordinate, so an OSV query
// for them was never going to return anything — and a reviewer reading a clean
// report has no way to tell that silence apart from a real all-clear. That is
// what this check exists to say out loud, and it is also why the same fact
// separately degrades scan coverage: the finding names the package, the
// coverage axis makes it reachable from an exit code.
//
// # When it escalates
//
// A non-registry source PLUS install-time code execution is a composed shape,
// not either half. A git dependency whose build script runs at install time
// carries an upstream that can change under a pin AND a mechanism to act on
// that change; that combination is worth gating on. A vendored crate with a
// build.rs is the same shape with a shorter blast radius — still worth
// surfacing, since in-tree source can be edited by anyone with commit access
// and no registry audit trail records it.
type UnverifiableSource struct{}

// Meta implements check.Check.
func (UnverifiableSource) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-009",
		Axis:            finding.AxisHygiene,
		DefaultSeverity: finding.SevLow,
		DefaultGate:     finding.GateAdvisory,
		Description:     "dependency resolved from a non-registry source (git, local path, direct URL): no advisory coverage",
	}
}

// Run implements check.Check.
func (UnverifiableSource) Run(ctx *check.Context) []finding.Finding {
	roots := map[string]bool{}
	for _, r := range ctx.Graph.Roots {
		roots[r] = true
	}

	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage || roots[n.ID] {
			// The project being scanned is local source by definition; it is
			// not a dependency of itself.
			continue
		}
		class, ref := n.SourceOf()
		// Only a recorded, non-registry class fires. A node whose adapter had
		// nothing to say about provenance is not a finding — absence of
		// evidence in a lockfile format is not evidence of a fork (D-41).
		if class == graph.SourceUnknown || graph.Verifiable(class) {
			continue
		}

		sev, gate, conf := finding.SevLow, finding.GateAdvisory, 0.5
		note := ""
		if hasInstallHook(ctx.Graph, n) {
			sev, gate, conf = finding.SevMedium, finding.GateEligible, 0.7
			note = "; it also declares install-time code, so a change to that source executes on install"
		}

		where := ""
		if ref != "" {
			where = fmt.Sprintf(" (%s)", ref)
		}

		out = append(out, finding.Finding{
			CheckID:    "VC-009",
			Axis:       finding.AxisHygiene,
			Severity:   sev,
			GateClass:  gate,
			Confidence: conf,
			NodeID:     n.ID,
			Title:      fmt.Sprintf("%s resolves from a %s source, not a registry", n.Name, class),
			Evidence: fmt.Sprintf(
				"source class %q%s: this package has no registry coordinate, so the advisory pass "+
					"over it could not have returned a finding%s",
				class, where, note),
			Remediation: sourceRemediation(class),
		})
	}
	return out
}

// sourceRemediation gives advice that fits the actual class, because the three
// cases call for genuinely different actions.
func sourceRemediation(class string) string {
	switch class {
	case graph.SourceGit:
		return "pin the dependency to an immutable commit rather than a tag or branch, and review the fork's " +
			"diff against its upstream; a tag can be moved after you audited it"
	case graph.SourcePath:
		return "review the vendored source in-repo as you would first-party code, and diff it against the " +
			"upstream release it forked from; no advisory feed covers it"
	default:
		return "confirm the artifact URL is one you control or trust, and record a checksum for it; " +
			"no advisory feed covers a package fetched this way"
	}
}
