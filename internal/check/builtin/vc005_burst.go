package builtin

import (
	"fmt"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// PatchBurst (VC-005) detects a cluster of releases around the pinned version —
// the ChainDrop republish tell, where a worm bumps the patch version of every
// package it infects and republishes in bulk.
//
// # Calibration
//
// A first run against a real 59-repo workspace produced 176 gate-eligible
// findings, overwhelmingly ordinary release trains: `@angular/*` ships ~20
// packages together several times a week, and `vite`, `undici` and `picomatch`
// release on similar cadences. The original anomaly test was `median > 24h`,
// which virtually every maintained package clears.
//
// The correction has two parts, and the second matters more:
//
//  1. A burst is only interesting on a package that is otherwise SLOW. A
//     package shipping weekly or faster is expected to cluster.
//  2. A burst ALONE is advisory, never gating. Release bursts are common and
//     benign; what is not benign is a burst on a package that also runs
//     install-time code. That is the composition the design brief called for —
//     "hook alone is low-confidence; hook + patch-burst is high-confidence" —
//     and it is what earns gate-eligible here.
//
// # Second calibration (Decision D-23)
//
// A later run still produced 92 findings, and 82 of them described bursts that
// had already decayed out of relevance: 38 were one to three years old, 37 were
// older than three years, and the oldest — `commondir@1.0.1` — was a release
// cluster from June 2015 being reported as supply-chain weather in 2026.
//
// This is the same defect D-21 fixed in VC-004, in a different file. The axis is
// "recent-compromise weather"; a burst that finished before the current
// maintainer took over is not weather. The floor below is deliberately the same
// constant as VC-004's and as verdict.StaleFloor: D-12 says a stale temporal
// finding may not gate, and D-21/D-23 say it is not a finding at all.
type PatchBurst struct{}

const (
	// burstWindow is the half-width of the cluster window: releases within this
	// much time either side of the pinned version count toward the burst.
	burstWindow = 24 * time.Hour
	// burstThreshold is how many releases in that window constitute a cluster.
	burstThreshold = 3
	// burstMinCadence is the slowest-normal boundary. A package whose median
	// inter-release gap is below this ships often enough that clustering is
	// expected, so a burst carries no information. Raised from 24h after the
	// Angular release-train false positives.
	burstMinCadence = 7 * 24 * time.Hour
	// burstMinRatio is how many times the expected release count the observed
	// cluster must reach before it is called anomalous.
	burstMinRatio = 3.0
	// burstMinDecay is the recency floor (Decision D-23). Below this the burst
	// is too old to be weather. It matches dormancyMinDecay and
	// verdict.StaleFloor — one constant, three checks, one meaning.
	burstMinDecay = 0.15
)

// Meta implements check.Check.
func (PatchBurst) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-005",
		Axis:            finding.AxisWeather,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "pinned version arrived in a release burst anomalous for this package",
		DataDeps:        []string{"npm-registry"},
	}
}

// Run implements check.Check.
func (PatchBurst) Run(ctx *check.Context) []finding.Finding {
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
		if h == nil || len(h.Releases) < burstThreshold {
			continue
		}
		idx := h.IndexOf(n.Version)
		if idx < 0 {
			continue
		}
		published := h.Releases[idx].Published
		count := h.CountAround(published, burstWindow)
		if count < burstThreshold {
			continue
		}

		median := h.MedianInterval()
		// A fast-shipping package is expected to cluster; say nothing.
		if median <= 0 || median < burstMinCadence {
			continue
		}
		// How many releases would this cadence predict inside the window?
		expected := (2 * burstWindow).Seconds() / median.Seconds()
		if expected <= 0 {
			expected = 0.01
		}
		ratio := float64(count) / expected
		if ratio < burstMinRatio {
			continue
		}

		// The burst must still be recent enough to count as weather (D-23).
		decay := datasource.Decay(now.Sub(published), datasource.DefaultHalfLife)
		if decay < burstMinDecay {
			continue
		}

		// A burst alone is ADVISORY. Only composition earns the gate.
		gate := finding.GateAdvisory
		conf := 0.35
		note := fmt.Sprintf("package normally releases every ~%s", roundDuration(median))
		if hasInstallHook(ctx.Graph, n) {
			gate = finding.GateEligible
			conf = 0.7
			note += "; package also declares an install hook, which is the shape that matters"
		}

		out = append(out, finding.Finding{
			CheckID:      "VC-005",
			Axis:         finding.AxisWeather,
			Severity:     finding.SevMedium,
			GateClass:    gate,
			Confidence:   conf,
			RecencyDecay: decay,
			NodeID:       n.ID,
			Title:        fmt.Sprintf("release burst around %s", n.Version),
			Evidence: fmt.Sprintf("%d releases within %s either side of %s (published %s) — %.0fx the %s expected at this cadence; %s",
				count, roundDuration(burstWindow), n.Version,
				published.UTC().Format("2006-01-02"), ratio, roundCount(expected), note),
			Remediation: "compare the release against its source commits — a patch bump with no matching commit is the republish signature",
		})
	}
	return out
}

// roundCount renders a small expected-count as a readable string.
func roundCount(f float64) string {
	if f < 1 {
		return fmt.Sprintf("%.2f", f)
	}
	return fmt.Sprintf("%.1f", f)
}

// roundDuration renders a duration in the largest sensible unit.
func roundDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}
