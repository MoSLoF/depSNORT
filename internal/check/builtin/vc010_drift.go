package builtin

import (
	"fmt"
	"strings"

	"ihbv.io/depsnort/internal/baseline"
	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/profile"
	"ihbv.io/depsnort/internal/semver"
)

// CapabilityDrift (VC-010) reports install-time capability a package gained
// relative to the version an operator promoted as known-good (Decision D-40).
//
// This is the axis every other check was missing. VC-002 asks what a package
// CAN do; VC-010 asks what it can do that it could not do last time. A
// postinstall hook that reads a named token and opens a socket is judged by
// VC-002d on its own merits — but a package that acquired that hook in a patch
// release, from a publisher who never shipped it before, after a year of
// silence, is a different and much more specific claim.
//
// # Weighting
//
// The weight is the package's own version number, because a version is a claim
// about how much should have changed. A major release that adds network access
// is doing what major releases do. The same addition in a patch release
// contradicts the claim its own version makes, and that contradiction — not the
// capability — is the signal.
//
// # Why this never blocks
//
// Block class is reserved for checks that judge a shape directly: a known
// malicious release (VC-001), an operator's own confirmed indicator (VC-003), a
// credential-exfiltration or download-cradle install path (VC-002d/f). Those
// conclusions stand on their own evidence. A drift finding stands on a
// COMPARISON, and the baseline side of that comparison is a file whose accuracy
// this tool cannot verify — it may have been recorded over an unread install
// surface, or promoted from a version that was already compromised. Gate-
// eligible is the honest ceiling for a conclusion resting on an input the
// operator supplied. If the drifted capability is genuinely a block-class
// shape, VC-002d/f will say so on their own.
type CapabilityDrift struct{}

// escalatingCaps are the capabilities whose ARRIVAL in a release that should
// not have changed much is worth gating on. Deliberately narrower than the full
// capability set: `env` is broad process-environment access, which legitimate
// native-build hooks read constantly, and gating on it would reproduce exactly
// the noise the VC-002 family was calibrated to avoid.
var escalatingCaps = map[string]bool{
	string(installsurface.CapCredentials): true,
	string(installsurface.CapCradle):      true,
	string(installsurface.CapObfuscation): true,
	string(installsurface.CapNetwork):     true,
	string(installsurface.CapExec):        true,
}

// Meta implements check.Check.
func (CapabilityDrift) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-010",
		Axis:            finding.AxisDrift,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "install-time capability gained relative to a known-good baseline",
		DataDeps:        []string{"baseline"},
	}
}

// Run implements check.Check.
func (CapabilityDrift) Run(ctx *check.Context) []finding.Finding {
	// No baseline, no opinion. The scan says so on stderr; a check that
	// invented a comparison here would be worse than silent.
	if len(ctx.Baseline) == 0 || len(ctx.Profiles) == 0 {
		return nil
	}

	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		candidate, ok := ctx.Profiles[n.ID]
		if !ok {
			continue
		}
		candidates := ctx.Baseline[baseline.Key(n.Ecosystem, n.Name)]
		if len(candidates) == 0 {
			// A package absent from the baseline is NEW to this tree, not
			// drifted. Reporting it here would drown the real signal in
			// every added dependency; VC-009 and the VC-002 family judge new
			// packages on their own merits.
			continue
		}

		base, ok := baseline.Lookup(candidates, n.ID, n.Version)
		if !ok {
			// Several approved versions and no exact match: nothing here can
			// say which one this candidate should be compared against, and the
			// answer depends on which project it came from rather than on any
			// ordering of versions (DS-REV-03). Guessing produces false drift
			// and suppresses real drift with equal confidence, so the check
			// declines — visibly.
			out = append(out, finding.Finding{
				CheckID:    "VC-010",
				Axis:       finding.AxisDrift,
				Severity:   finding.SevInfo,
				GateClass:  finding.GateAdvisory,
				Confidence: 1,
				NodeID:     n.ID,
				Title:      fmt.Sprintf("drift not evaluated for %s: ambiguous baseline", n.Name),
				Evidence: fmt.Sprintf(
					"the baseline approves %s at %d different versions (%s) and none of them is the "+
						"scanned version %s; comparing against an arbitrary one would report drift "+
						"that is an artifact of the choice",
					n.Name, len(candidates), strings.Join(baseline.Versions(candidates), ", "), n.Version),
				Remediation: "scan the project this baseline was taken from, or record a baseline whose " +
					"packages each appear at one approved version",
			})
			continue
		}

		// An exact version match means this version IS the approved one, so
		// there is nothing to compare and Diff correctly reports no change.
		d := profile.Diff(base, candidate)
		if !d.Escalating() {
			continue
		}

		sev, gate, conf := weighDrift(d)
		out = append(out, finding.Finding{
			CheckID:    "VC-010",
			Axis:       finding.AxisDrift,
			Severity:   sev,
			GateClass:  gate,
			Confidence: conf,
			NodeID:     n.ID,
			Title: fmt.Sprintf("%s gained install-time capability since %s (%s release)",
				n.Name, base.Version, d.Bump),
			Evidence:    driftEvidence(d, ctx, n),
			Remediation: "diff the two releases and confirm the new install-time behavior is intended and reviewed; if it is not explained by the changelog, treat the release as suspect",
		})
	}
	return out
}

// weighDrift turns a diff into severity, gate class, and confidence.
//
// The two axes are what arrived and how big a change the version claimed to be.
// A patch or minor release is a claim of "nothing structural changed here"; a
// major release makes no such claim, so the same addition is ordinary and stays
// advisory. An unparseable version pair (BumpUnknown) is treated like a minor:
// the claim could not be read, which is not the same as a claim of safety, but
// is thin ground for a confident escalation.
func weighDrift(d profile.Drift) (finding.Severity, finding.GateClass, float64) {
	var arrived []string
	arrived = append(arrived, d.AddedCaps...)

	dangerous := false
	for _, c := range arrived {
		if escalatingCaps[c] {
			dangerous = true
			break
		}
	}
	// A newly declared install hook is itself an escalation even when no
	// capability was recovered from it — often BECAUSE none was, since an
	// unreadable hook is exactly the case where the capability list is a lower
	// bound.
	newHook := len(d.AddedHooks) > 0
	newSink := len(d.AddedSinks) > 0

	switch d.Bump {
	case semver.BumpPatch, semver.BumpMinor, semver.BumpNone:
		switch {
		case newSink || containsAny(arrived, string(installsurface.CapCredentials),
			string(installsurface.CapCradle), string(installsurface.CapObfuscation)):
			return finding.SevHigh, finding.GateEligible, 0.75
		case dangerous || newHook:
			return finding.SevMedium, finding.GateEligible, 0.6
		default:
			return finding.SevLow, finding.GateAdvisory, 0.4
		}
	case semver.BumpMajor:
		// A major release is allowed to grow. Still reported — a reviewer
		// comparing releases wants to see it — but it does not gate.
		if newSink || dangerous {
			return finding.SevMedium, finding.GateAdvisory, 0.45
		}
		return finding.SevLow, finding.GateAdvisory, 0.35
	default: // BumpUnknown
		if newSink || dangerous || newHook {
			return finding.SevMedium, finding.GateEligible, 0.5
		}
		return finding.SevLow, finding.GateAdvisory, 0.35
	}
}

// driftEvidence renders the delta, and composes it with whatever else this scan
// already knows about the package.
//
// The composition is the point (D-40). "foo 1.6.3 newly declares a postinstall
// hook with credential access relative to 1.6.2, was published by an account
// that has never published this package, and appeared after 420 days of
// dormancy" is a different claim from any of its three parts, and an operator
// should not have to assemble it by cross-referencing three findings.
func driftEvidence(d profile.Drift, ctx *check.Context, n *graph.Node) string {
	var parts []string
	if len(d.AddedHooks) > 0 {
		parts = append(parts, "new install hook(s): "+strings.Join(d.AddedHooks, ", "))
	}
	if len(d.AddedCaps) > 0 {
		parts = append(parts, "new capabilit(ies): "+strings.Join(d.AddedCaps, ", "))
	}
	if len(d.AddedSinks) > 0 {
		parts = append(parts, "new credential sink(s): "+strings.Join(d.AddedSinks, ", "))
	}
	if len(d.AddedRemoteHosts) > 0 {
		parts = append(parts, "new remote host(s): "+strings.Join(d.AddedRemoteHosts, ", "))
	}
	if d.SourceClassChanged {
		parts = append(parts, fmt.Sprintf("source changed %s -> %s", d.FromSourceClass, d.ToSourceClass))
	}
	if d.TopologyChanged {
		parts = append(parts, "direct dependencies changed")
	}

	evidence := fmt.Sprintf("%s -> %s (%s): %s",
		d.From, d.To, d.Bump, strings.Join(parts, "; "))

	// Actor context, when the registry gave us any.
	switch {
	case d.PublisherChanged:
		evidence += fmt.Sprintf("; published by %s, where the baseline version was published by %s",
			d.ToPublisher, d.FromPublisher)
	case d.PublisherUnknown:
		evidence += "; publisher identity unavailable for at least one side, so the actor axis is unevaluated"
	}

	// Temporal context, from the same release history VC-004/VC-005 read.
	if h := ctx.Releases[n.ID]; h != nil {
		if idx := h.IndexOf(n.Version); idx > 0 {
			gap := h.Releases[idx].Published.Sub(h.Releases[idx-1].Published)
			if gap >= dormancyThreshold {
				evidence += fmt.Sprintf("; the drifted release also arrived after %s of dormancy",
					roundDuration(gap))
			}
		}
	}

	// The lower-bound note is about the CAPABILITY delta, so the publisher
	// marker is filtered out: its consequence is the actor clause immediately
	// above, and repeating it here would read as a second, separate defect.
	var bounds []string
	for _, u := range d.Unobservable {
		if u != profile.UnobservedPublisher {
			bounds = append(bounds, u)
		}
	}
	if len(bounds) > 0 {
		evidence += fmt.Sprintf("; this delta is a LOWER BOUND (%s)", strings.Join(bounds, ", "))
	}
	return evidence
}

func containsAny(list []string, want ...string) bool {
	for _, v := range list {
		for _, w := range want {
			if v == w {
				return true
			}
		}
	}
	return false
}
