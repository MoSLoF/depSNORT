package builtin

import (
	"fmt"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// Dormancy (VC-004) reports a version published RECENTLY after a long quiet
// period — the classic maintainer-account-takeover shape, where an abandoned but
// widely depended-on package suddenly ships again.
//
// # Calibration
//
// A real 59-repo workspace produced **687 VC-004 findings** — roughly a fifth of
// every package with registry data. The cause was scope, not thresholds: the
// check flagged any gap over a year ANYWHERE in a package's history, including
// gaps that closed half a decade ago.
//
// That is not weather, it is climate history. A mature library that sat still
// for two years and then shipped a maintenance release in 2019 is evidence of
// stability, not compromise — and if you are pinned to that release, the
// awakening is long since settled.
//
// The axis is "recent-compromise weather" (brief §4), so the check now reports
// only awakenings still inside the decay-relevant window. An old awakening is
// out of scope by definition rather than suppressed: the same reasoning that
// demotes stale temporal findings from gating in D-12, applied one step earlier.
type Dormancy struct{}

// dormancyThreshold is how long a package must be quiet for its next release to
// count as an awakening.
const dormancyThreshold = 365 * 24 * time.Hour

// dormancyMinDecay is the recency floor. Below this the awakening is too old to
// be "weather" — it matches verdict.StaleFloor, which is the level at which a
// temporal finding already loses the right to gate.
const dormancyMinDecay = 0.15

// Meta implements check.Check.
func (Dormancy) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-004",
		Axis:            finding.AxisWeather,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "version published recently after prolonged dormancy (possible account takeover)",
		DataDeps:        []string{"npm-registry"},
	}
}

// Run implements check.Check.
func (Dormancy) Run(ctx *check.Context) []finding.Finding {
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
		if h == nil || len(h.Releases) < 2 {
			continue
		}
		idx := h.IndexOf(n.Version)
		if idx < 1 {
			continue // first-ever release has no dormancy to measure
		}

		// Walk backward through a cluster of rapid releases to find the
		// boundary where the dormancy gap actually lives. Without this,
		// an attacker who publishes v1.0.1, v1.0.2, v1.0.3 in quick
		// succession after years of silence defeats the check when the
		// user pins v1.0.3, because idx-1 is v1.0.2, not the dormant
		// boundary.
		clusterStart := idx
		for clusterStart > 1 {
			prev := h.Releases[clusterStart-1].Published
			cur := h.Releases[clusterStart].Published
			if cur.Sub(prev) >= dormancyThreshold {
				break
			}
			clusterStart--
		}
		gap := h.Releases[clusterStart].Published.Sub(h.Releases[clusterStart-1].Published)
		if gap < dormancyThreshold {
			continue
		}
		clusterPub := h.Releases[clusterStart].Published

		// The awakening must still be recent enough to count as weather.
		decay := datasource.Decay(now.Sub(clusterPub), datasource.DefaultHalfLife)
		if decay < dormancyMinDecay {
			continue
		}

		gate := finding.GateAdvisory
		sev := finding.SevMedium
		conf := 0.4
		note := ""
		if hasInstallHook(ctx.Graph, n) {
			gate = finding.GateEligible
			sev = finding.SevHigh
			conf = 0.65
			note = "; the awakening release also declares an install hook"
		}

		beforeVer := h.Releases[clusterStart-1].Version
		beforePub := h.Releases[clusterStart-1].Published
		afterVer := h.Releases[clusterStart].Version

		out = append(out, finding.Finding{
			CheckID:      "VC-004",
			Axis:         finding.AxisWeather,
			Severity:     sev,
			GateClass:    gate,
			Confidence:   conf,
			RecencyDecay: decay,
			NodeID:       n.ID,
			Title:        fmt.Sprintf("%s published after %s of dormancy", n.Version, roundDuration(gap)),
			Evidence: fmt.Sprintf("dormancy gap: %s -> %s (%s, %s -> %s)%s",
				beforeVer, afterVer, roundDuration(gap),
				beforePub.UTC().Format("2006-01-02"),
				clusterPub.UTC().Format("2006-01-02"), note),
			Remediation: "verify the publishing account and confirm the release corresponds to reviewed source changes",
		})
	}
	return out
}
