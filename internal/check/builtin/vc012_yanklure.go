package builtin

import (
	"fmt"
	"sort"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/semver"
)

// YankLure (VC-012) reports a resolved dependency pinned to a version the
// registry has YANKED, and elevates it when the crate also shows the yank-lure
// shape the 2026-08-20 crates.io compromise used (arrayref / proc-macro1).
//
// # The two halves
//
// The anchor is concrete and low-FP: a lockfile pins a version whose maintainer
// explicitly withdrew it ("do not use this release"). A fresh resolution would
// refuse it; a lockfile carries it forward silently, so it is worth surfacing on
// its own.
//
// The elevation is the attack shape. In a yank-lure, an attacker who has taken
// over a maintainer account yanks the good releases and publishes a malicious one
// as the newest LIVE version. cargo then nudges every consumer of a yanked
// version toward "a version that is not yanked" — which points straight at the
// payload. So a pinned-yanked dependency whose crate's highest live version sits
// atop a contiguous run of yanked versions is not just stale: it is a consumer
// standing exactly where the lure funnels an upgrade. The finding says inspect
// that newest version before upgrading, rather than accepting cargo's nudge.
//
// # Scope
//
// crates.io is the only registry of the six that exposes a per-version yanked
// flag in the metadata depsnort fetches, so a false Release.Yanked elsewhere means
// "unknown", not "live". VC-012 therefore evaluates only cargo nodes — reading an
// always-false flag on the other five would be a silent miss dressed as an
// all-clear (D-24). The introduced-dependency corroborators the attack also leaves
// (a new build-dep, a typosquat neighbor, a hostile build.rs) live in the live-newest
// version that is not in the resolved graph, and are a later increment.
type YankLure struct{}

// Meta implements check.Check.
func (YankLure) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-012",
		Axis:            finding.AxisWeather,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "dependency pinned to a yanked version; elevated on the yank-lure shape",
		DataDeps:        []string{"cargo-registry"},
	}
}

// yankLureMinRun is how many contiguous yanked versions must sit beneath the live
// newest for the lure shape to engage. One yank is routine (a buggy release
// pulled); a run is the mass-yank an attacker performs to make the payload the
// only "non-yanked" option cargo will offer.
const yankLureMinRun = 2

// Run implements check.Check.
func (YankLure) Run(ctx *check.Context) []finding.Finding {
	if len(ctx.Releases) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "cargo" {
			continue // yank data is only trustworthy where the registry supplies it
		}
		h := ctx.Releases[n.ID]
		if h == nil {
			continue
		}
		// The anchor: is the PINNED version yanked?
		pinnedYanked := false
		found := false
		for _, r := range h.Releases {
			if r.Version == n.Version {
				pinnedYanked = r.Yanked
				found = true
				break
			}
		}
		if !found || !pinnedYanked {
			continue
		}

		sev := finding.SevMedium
		gate := finding.GateAdvisory
		conf := 0.5
		title := fmt.Sprintf("dependency pinned to yanked version %s", n.Version)
		evidence := fmt.Sprintf("%s@%s is yanked on the registry (the maintainer withdrew it); a fresh resolution would not select it", n.Name, n.Version)
		remediation := "move off the yanked version deliberately — but inspect the target before upgrading (see below if a yank-lure shape is present)"

		if newest, run, ok := yankLureEndState(h); ok {
			sev = finding.SevHigh
			gate = finding.GateEligible
			conf = 0.7
			title = fmt.Sprintf("yank-lure: pinned to yanked %s beneath a live newest %s", n.Version, newest)
			evidence = fmt.Sprintf("%s@%s is yanked, and the crate's highest live version %s sits atop a contiguous run of %d yanked versions — "+
				"the yank-lure shape (cf. arrayref/proc-macro1, 2026-08-20): cargo nudges a yanked-version consumer toward the newest non-yanked release, which is exactly where an account-takeover attacker plants the payload",
				n.Name, n.Version, newest, run)
			remediation = fmt.Sprintf("do NOT blindly upgrade to %s: inspect its introduced dependencies and build.rs first — the yanked run below it is the lure, and the live newest is the version to audit", newest)
		}

		out = append(out, finding.Finding{
			CheckID:      "VC-012",
			Axis:         finding.AxisWeather,
			Severity:     sev,
			GateClass:    gate,
			Confidence:   conf,
			RecencyDecay: 1.0, // a yanked pin is a present-tense fact, not a decaying event
			NodeID:       n.ID,
			Title:        title,
			Evidence:     evidence,
			Remediation:  remediation,
		})
	}
	return out
}

// yankLureEndState reports the yank-lure shape: the crate's highest SEMVER version
// is LIVE (not yanked) and is immediately preceded, in semver order, by a
// contiguous run of >= yankLureMinRun yanked versions. It returns the live newest
// version and the run length. Ordering is by semver, not publish time, because
// cargo's "select a non-yanked version" nudge resolves by version, not by when a
// release happened to be indexed.
func yankLureEndState(h *datasource.ReleaseHistory) (newest string, run int, ok bool) {
	rs := append([]datasource.Release(nil), h.Releases...)
	sort.Slice(rs, func(i, j int) bool {
		return semver.Parse(rs[i].Version).Compare(semver.Parse(rs[j].Version)) < 0
	})
	if len(rs) < yankLureMinRun+1 {
		return "", 0, false
	}
	top := rs[len(rs)-1]
	if top.Yanked {
		return "", 0, false // the payload version stays live; a yanked newest is not the lure
	}
	for i := len(rs) - 2; i >= 0; i-- {
		if !rs[i].Yanked {
			break
		}
		run++
	}
	if run >= yankLureMinRun {
		return top.Version, run, true
	}
	return "", 0, false
}
