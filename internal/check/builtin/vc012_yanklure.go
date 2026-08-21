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
// Three ecosystems expose a per-version withdrawal flag in the metadata depsnort
// fetches: crates.io (yank), PyPI (PEP 592 yank), and Go (go.mod retract). On the
// other three Release.Yanked stays false and means "unknown", not "live", so VC-012
// evaluates only cargo, PyPI, and Go nodes — reading an always-false flag elsewhere
// would be a silent miss dressed as an all-clear (D-24). The payload corroborators
// the attack also leaves (a new build-dep, a typosquat neighbor, a hostile build.rs
// or setup.py) live in the live-newest version that is not in the resolved graph;
// they are cargo/PyPI-only, since a Go retract carries no install hook — Go module
// code runs on import, so the Go finding is the shape advisory alone.
type YankLure struct{}

// Meta implements check.Check.
func (YankLure) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-012",
		Axis:            finding.AxisWeather,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "dependency pinned to a yanked version; elevated on the yank-lure shape",
		DataDeps:        []string{"cargo-registry", "pypi-registry", "gomod-registry"},
	}
}

// attrIntroducedBuildDeps is the node attribute the yank-lure enrichment stage
// writes (comma-joined): the BUILD dependencies the crate's live-newest version
// introduces versus the pinned version. VC-012 reads it to corroborate the shape.
const attrIntroducedBuildDeps = "yanklure.introduced_build_deps"

// attrHostileBuildDeps is the subset of the introduced build-deps whose own
// build.rs statically exhibits the compile-time payload shape (Increment 3).
const attrHostileBuildDeps = "yanklure.hostile_build_deps"

// attrHostileNewest holds the live-newest version whose OWN install hook (setup.py)
// is hostile — the PyPI payload analogue, where the malicious release ships the
// payload in its own setup.py rather than in an introduced dependency (Increment 5).
const attrHostileNewest = "yanklure.hostile_newest"

// yankLureEco describes how one ecosystem words and shapes a version withdrawal,
// so VC-012's evidence reads in that ecosystem's own terms.
type yankLureEco struct {
	// installer is the tool whose "select a non-withdrawn version" nudge is the lure
	// (cargo, pip, go).
	installer string
	// hook is the install/build-time hook file an attacker plants the payload in
	// (build.rs, setup.py). Empty for gomod: a Go module has no discrete install
	// hook — its code simply runs on import — so the shape is advisory-only, with no
	// hostile-hook escalation path in this increment.
	hook string
	// verb is how the registry words the withdrawal ("yanked" for cargo/PyPI,
	// "retracted" for Go), used verbatim in the finding text.
	verb string
	// lure names the attack shape ("yank-lure", "retract-lure").
	lure string
}

// yankLureRegistry returns how VC-012 should treat an ecosystem, and ok = whether it
// evaluates it at all. cargo (yank), PyPI (PEP 592 yank), and Go (go.mod retract) all
// make a withdrawn version un-selectable in a fresh resolution while keeping it usable
// when already pinned — the asymmetry the lure exploits. Elsewhere Release.Yanked is
// always false and means "unknown", so the check does not run: reading it as "live"
// would be a silent miss dressed as clean (D-24). The introduced-dependency and
// hostile-hook corroborators (Increments 2-3, 5) are cargo/PyPI-only; a Go node gets
// the shape finding alone, since a retract carries no install-hook to inspect.
func yankLureRegistry(ecosystem string) (yankLureEco, bool) {
	switch ecosystem {
	case "cargo":
		return yankLureEco{installer: "cargo", hook: "build.rs", verb: "yanked", lure: "yank-lure"}, true
	case "pypi":
		return yankLureEco{installer: "pip", hook: "setup.py", verb: "yanked", lure: "yank-lure"}, true
	case "gomod":
		return yankLureEco{installer: "go", hook: "", verb: "retracted", lure: "retract-lure"}, true
	}
	return yankLureEco{}, false
}

// Run implements check.Check.
func (YankLure) Run(ctx *check.Context) []finding.Finding {
	if len(ctx.Releases) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		eco, evaluable := yankLureRegistry(n.Ecosystem)
		if n.Kind != graph.KindPackage || !evaluable {
			continue // yank data is only trustworthy where the registry supplies it
		}
		h := ctx.Releases[n.ID]
		if h == nil {
			continue
		}
		// The anchor: is the PINNED version withdrawn?
		if yanked, known := h.IsYanked(n.Version); !known || !yanked {
			continue
		}

		sev := finding.SevMedium
		gate := finding.GateAdvisory
		conf := 0.5
		title := fmt.Sprintf("dependency pinned to %s version %s", eco.verb, n.Version)
		evidence := fmt.Sprintf("%s@%s is %s on the registry (the maintainer withdrew it); a fresh resolution would not select it", n.Name, n.Version, eco.verb)
		remediation := fmt.Sprintf("move off the %s version deliberately — but inspect the target before upgrading (see below if a %s shape is present)", eco.verb, eco.lure)

		if newest, run, ok := h.YankLureShape(); ok {
			sev = finding.SevHigh
			gate = finding.GateEligible
			conf = 0.7
			title = fmt.Sprintf("%s: pinned to %s %s beneath a live newest %s", eco.lure, eco.verb, n.Version, newest)
			evidence = fmt.Sprintf("%s@%s is %s, and the package's highest live version %s sits atop a contiguous run of %d %s versions — "+
				"the %s shape (cf. arrayref/proc-macro1, 2026-08-20): %s nudges a %s-version consumer toward the newest non-%s release, which is exactly where an account-takeover attacker plants the payload",
				n.Name, n.Version, eco.verb, newest, run, eco.verb, eco.lure, eco.installer, eco.verb, eco.verb)
			inspect := "its introduced dependencies and " + eco.hook
			if eco.hook == "" {
				inspect = "its code (which runs on import)"
			}
			remediation = fmt.Sprintf("do NOT blindly upgrade to %s: inspect %s first — the %s run below it is the lure, and the live newest is the version to audit", newest, inspect, eco.verb)

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
				// Increment 3: the introduced build-dep's own build.rs statically exhibits
				// the compile-time payload shape (network + exec/obfuscation). This is the
				// payload itself, not a name-similarity heuristic — critical, and it fires
				// even when the dep's name is NOT a typosquat.
				if hostile := splitAttr(n.Attr[attrHostileBuildDeps]); len(hostile) > 0 {
					sev = finding.SevCritical
					conf = 0.95
					evidence += fmt.Sprintf("; introduced build-dep ships a HOSTILE build.rs (network + exec/obfuscation): %s", strings.Join(hostile, ", "))
					remediation = fmt.Sprintf("do NOT upgrade %s: the version cargo nudges toward pulls a build dependency whose build.rs runs network + code-execution at compile time — treat as an active compromise and report the crate", n.Name)
				}
			}

			// Increment 5 (PyPI payload): the live-newest's OWN install hook is hostile.
			// Unlike cargo — where the payload rides an introduced build-dep — a malicious
			// PyPI release usually ships the payload in its own setup.py, run by pip at
			// install. This escalates to CRITICAL on its own, independent of any dep diff.
			if hn := n.Attr[attrHostileNewest]; hn != "" {
				sev = finding.SevCritical
				conf = 0.95
				evidence += fmt.Sprintf("; the live newest %s ships a HOSTILE %s (network + exec/obfuscation at install time)", hn, eco.hook)
				remediation = fmt.Sprintf("do NOT upgrade %s: the version %s nudges toward runs network + code-execution in its %s at install — treat as an active compromise and report the package", n.Name, eco.installer, eco.hook)
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
