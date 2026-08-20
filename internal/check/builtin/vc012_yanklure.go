package builtin

import (
	"fmt"
	"strings"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
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

// attrIntroducedBuildDeps is the node attribute the yank-lure enrichment stage
// writes (comma-joined): the BUILD dependencies the crate's live-newest version
// introduces versus the pinned version. VC-012 reads it to corroborate the shape.
const attrIntroducedBuildDeps = "yanklure.introduced_build_deps"

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
		if yanked, known := h.IsYanked(n.Version); !known || !yanked {
			continue
		}

		sev := finding.SevMedium
		gate := finding.GateAdvisory
		conf := 0.5
		title := fmt.Sprintf("dependency pinned to yanked version %s", n.Version)
		evidence := fmt.Sprintf("%s@%s is yanked on the registry (the maintainer withdrew it); a fresh resolution would not select it", n.Name, n.Version)
		remediation := "move off the yanked version deliberately — but inspect the target before upgrading (see below if a yank-lure shape is present)"

		if newest, run, ok := h.YankLureShape(); ok {
			sev = finding.SevHigh
			gate = finding.GateEligible
			conf = 0.7
			title = fmt.Sprintf("yank-lure: pinned to yanked %s beneath a live newest %s", n.Version, newest)
			evidence = fmt.Sprintf("%s@%s is yanked, and the crate's highest live version %s sits atop a contiguous run of %d yanked versions — "+
				"the yank-lure shape (cf. arrayref/proc-macro1, 2026-08-20): cargo nudges a yanked-version consumer toward the newest non-yanked release, which is exactly where an account-takeover attacker plants the payload",
				n.Name, n.Version, newest, run)
			remediation = fmt.Sprintf("do NOT blindly upgrade to %s: inspect its introduced dependencies and build.rs first — the yanked run below it is the lure, and the live newest is the version to audit", newest)

			// Increment-2 corroboration: the enrichment stage recorded the BUILD
			// dependencies the live-newest introduces vs the pinned version. A new
			// build-dep is the arrayref tell; a new build-dep that is a typosquat of a
			// popular crate (proc-macro1 vs proc-macro2) is the signature — escalate.
			if introduced := splitAttr(n.Attr[attrIntroducedBuildDeps]); len(introduced) > 0 {
				conf = 0.8
				evidence += fmt.Sprintf("; %s introduces build-dependenc%s not in %s: %s",
					newest, plural(len(introduced), "y", "ies"), n.Version, strings.Join(introduced, ", "))
				var squats []string
				for _, dep := range introduced {
					if orig, ok := cargoTyposquatNeighbor(dep); ok {
						squats = append(squats, fmt.Sprintf("%s~%s", dep, orig))
					}
				}
				if len(squats) > 0 {
					sev = finding.SevCritical
					conf = 0.9
					evidence += fmt.Sprintf("; introduced build-dep is a TYPOSQUAT of a popular crate: %s", strings.Join(squats, ", "))
					remediation = fmt.Sprintf("treat %s as a live supply-chain compromise: the live newest introduces a typosquatted build dependency that runs at compile time — do not upgrade, and report the crate", n.Name)
				}
			}
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

// splitAttr splits a comma-joined node attribute into its non-empty parts.
func splitAttr(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cargoTyposquatTargets is a focused list of high-reach crates that a build-time
// dependency name is scored against — deliberately small and build-relevant
// (proc-macro / derive / sys-crate territory, where a compile-time typosquat like
// proc-macro1 -> proc-macro2 does its work), not a general popularity corpus. It is
// used only by VC-012's introduced-build-dep check; the general typosquat corpus
// (VC-006) does not yet cover cargo, and widening it is its own calibration.
var cargoTyposquatTargets = []string{
	"proc-macro2", "syn", "quote", "serde", "serde_derive", "serde_json",
	"libc", "cc", "cxx", "bindgen", "pkg-config", "cmake", "autocfg",
	"tokio", "futures", "async-trait", "once_cell", "lazy_static",
	"anyhow", "thiserror", "log", "tracing", "rand", "regex", "bytes", "clap",
}

// cargoTyposquatNeighbor reports whether an introduced build-dependency name is a
// distance-1 near-miss of a known high-reach crate (and not that crate itself) —
// the proc-macro1 / proc-macro2 shape. Distance 1 only: a build-dep name one edit
// from a popular crate is the compile-time typosquat vector; wider distances are
// left to a fuller cargo corpus.
func cargoTyposquatNeighbor(name string) (target string, ok bool) {
	for _, p := range cargoTyposquatTargets {
		if name == p {
			return "", false // it IS the popular crate
		}
		if osaDistanceBounded(name, p, 1) == 1 {
			return p, true
		}
	}
	return "", false
}
