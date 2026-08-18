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
// support the claim "this publisher is new".
//
// Between those two states sits a third that used to be treated as the first
// (finding DS-REV-04): a PARTIALLY recorded history. Given alice / unknown /
// mallory, the unknown release could have been mallory's, so the evidence
// supports "mallory is not among the publishers we can see" and nothing
// stronger. Such a finding is reported with the qualification in its own title
// and evidence, at reduced confidence, and never gates however it composes —
// composition multiplies confidence, and there is none here to multiply. On
// crates.io this is the normal shape rather than an edge case: published_by
// postdates most releases of most crates.
type PublisherLineage struct{}

// capSeverity lowers sev to max when it is more severe, and leaves it alone
// otherwise.
//
// Written as an explicit rank rather than a comparison on the Severity values:
// Severity is a string type, so `sev > finding.SevMedium` compares "high"
// against "medium" LEXICOGRAPHICALLY and is false — the cap would silently
// never apply, on the one path whose whole purpose is to weaken a claim.
func capSeverity(sev, max finding.Severity) finding.Severity {
	rank := map[finding.Severity]int{
		finding.SevInfo: 0, finding.SevLow: 1, finding.SevMedium: 2,
		finding.SevHigh: 3, finding.SevCritical: 4,
	}
	if rank[sev] > rank[max] {
		return max
	}
	return sev
}

// lineageTitle keeps the headline as precise as the evidence behind it. A
// reader who only sees the title must not come away with a stronger claim than
// the evidence supports.
func lineageTitle(version, who string, complete bool) string {
	if complete {
		return fmt.Sprintf("%s published by %s, who has not published this package before", version, who)
	}
	return fmt.Sprintf("%s published by %s, who is not among this package's recorded publishers", version, who)
}

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
		prior := h.PriorPublishers(n.Version)
		if !prior.Evaluable() {
			continue // no earlier identity to compare against: unevaluable
		}
		if prior.Seen(pub.Key()) {
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

		// A PARTIAL prior history cannot carry a definitive claim (finding
		// DS-REV-04). With gaps in the record, "this publisher is new" may
		// simply mean the publisher is sitting in one of the gaps: a history of
		// alice / unknown / mallory supports "mallory is not among the
		// publishers we can see" and nothing stronger, because the unknown
		// release could have been mallory's.
		//
		// The claim is weakened rather than dropped. It is still worth
		// surfacing — but it must not gate, however it composes, because
		// composition multiplies confidence and there is none to multiply.
		// This is not an edge case: on crates.io most releases of most crates
		// predate published_by, so partial is the normal shape there.
		claim := fmt.Sprintf("appears in no earlier release of %s", n.Name)
		if !prior.Complete() {
			claim = fmt.Sprintf(
				"is not among the %d recorded prior publisher(s) of %s, though %d earlier release(s) "+
					"record no publisher at all — this is a LOWER BOUND, not a first-time-publisher claim",
				prior.Recorded, n.Name, prior.Unrecorded)
			gate = finding.GateAdvisory
			sev = capSeverity(sev, finding.SevMedium)
			conf *= 0.5
			composed += "; the prior publisher record is incomplete, so this cannot establish a first release from this account"
		}

		out = append(out, finding.Finding{
			CheckID:      "VC-011",
			Axis:         finding.AxisWeather,
			Severity:     sev,
			GateClass:    gate,
			Confidence:   conf,
			RecencyDecay: decay,
			NodeID:       n.ID,
			Title:        lineageTitle(n.Version, pub.Name, prior.Complete()),
			Evidence: fmt.Sprintf(
				"publisher %q (%s, via %s) %s%s",
				pub.Name, pub.Key(), pub.Source, claim, composed),
			Remediation: "confirm the publishing account is a legitimate maintainer and that the release " +
				"corresponds to reviewed source changes; a first release from a new account is normal, " +
				"a first release from a new account that also runs code at install time is worth verifying",
		})
	}
	return out
}
