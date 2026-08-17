package builtin

import (
	"fmt"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// PublisherLineage (VC-011) reports that the pinned version was published by an
// account that has never published this package before (Decision D-40).
//
// # Why this cannot gate on its own
//
// New publishers are ordinary. Maintainers hand projects over, organizations
// rotate release engineering, a co-maintainer cuts their first release, a
// project migrates to a CI publishing token. Every one of those produces a
// first-time publisher, and none of them is a compromise. A check that gated on
// actor change alone would fire constantly on healthy projects and be muted
// within a week — which would also mute it for the case it exists for.
//
// # What makes it matter
//
// The takeover shape is a first-time publisher arriving TOGETHER with something
// else: a package waking from dormancy, a burst of releases against the
// package's own cadence, or install-time capability that was not there before.
// Any of those alone is weak. The conjunction is specific, and it is what this
// check escalates on — the same composition discipline as VC-004 and VC-005,
// applied to the actor axis.
//
// # Absence is not continuity
//
// Four of the six ecosystems publish no per-version uploader at all, and even
// npm and crates.io have releases predating the fields that carry it. Where the
// prior releases carry no identity, this check produces NOTHING rather than a
// finding, because "we cannot see who published the earlier versions" cannot
// support the claim "this publisher is new". That is what
// ReleaseHistory.PriorPublishers's `known` flag exists to enforce.
type PublisherLineage struct{}

// lineageMinDecay is the recency floor, matching VC-004. A first-time publisher
// whose release is years old is settled history: if it were a takeover, the
// evidence would have surfaced through some other axis long ago, and reporting
// it now is climate rather than weather.
const lineageMinDecay = 0.15

// Meta implements check.Check.
func (PublisherLineage) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-011",
		Axis:            finding.AxisWeather,
		DefaultSeverity: finding.SevLow,
		DefaultGate:     finding.GateAdvisory,
		Description:     "version published by an account with no prior release of this package",
		DataDeps:        []string{"npm-registry", "cargo-registry"},
	}
}

// Run implements check.Check.
func (PublisherLineage) Run(ctx *check.Context) []finding.Finding {
	if len(ctx.Releases) == 0 {
		return nil
	}
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}

	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		h := ctx.Releases[n.ID]
		if h == nil {
			continue
		}
		pub, ok := h.PublisherAt(n.Version)
		if !ok {
			continue // this ecosystem or this release records no publisher
		}
		prior, known := h.PriorPublishers(n.Version)
		if !known {
			continue // no earlier identity to compare against: unevaluable
		}
		if prior[pub.Key()] {
			continue // this account has shipped this package before
		}

		idx := h.IndexOf(n.Version)
		if idx < 1 {
			continue // a package's first-ever release has no lineage to break
		}
		published := h.Releases[idx].Published
		decay := datasource.Decay(now.Sub(published), datasource.DefaultHalfLife)
		if decay < lineageMinDecay {
			continue
		}

		sev, gate, conf := finding.SevLow, finding.GateAdvisory, 0.35
		var composed string

		gap := published.Sub(h.Releases[idx-1].Published)
		switch {
		case hasInstallHook(ctx.Graph, n):
			// A new actor plus install-time code execution is the shape that
			// matters: the account that changed is the one whose next release
			// runs on every consumer's machine.
			sev, gate, conf = finding.SevHigh, finding.GateEligible, 0.65
			composed = "; the release also declares an install hook"
		case gap >= dormancyThreshold:
			sev, gate, conf = finding.SevMedium, finding.GateEligible, 0.6
			composed = fmt.Sprintf("; it also ended %s of dormancy", roundDuration(gap))
		}

		out = append(out, finding.Finding{
			CheckID:      "VC-011",
			Axis:         finding.AxisWeather,
			Severity:     sev,
			GateClass:    gate,
			Confidence:   conf,
			RecencyDecay: decay,
			NodeID:       n.ID,
			Title: fmt.Sprintf("%s published by %s, who has not published this package before",
				n.Version, pub.Name),
			Evidence: fmt.Sprintf(
				"publisher %q (%s, via %s) appears in no earlier release of %s; %d prior publisher(s) on record%s",
				pub.Name, pub.Key(), pub.Source, n.Name, len(prior), composed),
			Remediation: "confirm the publishing account is a legitimate maintainer and that the release " +
				"corresponds to reviewed source changes; a first release from a new account is normal, " +
				"a first release from a new account that also runs code at install time is worth verifying",
		})
	}
	return out
}
