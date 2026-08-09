package datasource

import (
	"math"
	"sort"
	"time"
)

// Release is one published version of a package.
type Release struct {
	Version   string    `json:"version"`
	Published time.Time `json:"published"`
}

// ReleaseHistory is a package's publish timeline — the substrate of the
// temporal ("recent-compromise weather") axis. A lockfile pins exactly one
// version and carries no history, so this can only come from a registry.
type ReleaseHistory struct {
	Package     string    `json:"package"`
	Ecosystem   string    `json:"ecosystem"`
	Releases    []Release `json:"releases"` // sorted oldest -> newest
	Maintainers []string  `json:"maintainers,omitempty"`
}

// Sort orders releases oldest to newest.
func (h *ReleaseHistory) Sort() {
	sort.Slice(h.Releases, func(i, j int) bool {
		return h.Releases[i].Published.Before(h.Releases[j].Published)
	})
}

// IndexOf returns the position of version in the sorted history, or -1.
func (h *ReleaseHistory) IndexOf(version string) int {
	for i, r := range h.Releases {
		if r.Version == version {
			return i
		}
	}
	return -1
}

// MedianInterval returns the median gap between consecutive releases. It is the
// package's own baseline cadence — anomaly is measured against this rather than
// a global constant, because a daily-release package and a yearly-release
// package have very different "normal".
func (h *ReleaseHistory) MedianInterval() time.Duration {
	if len(h.Releases) < 3 {
		return 0
	}
	gaps := make([]time.Duration, 0, len(h.Releases)-1)
	for i := 1; i < len(h.Releases); i++ {
		g := h.Releases[i].Published.Sub(h.Releases[i-1].Published)
		if g > 0 {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) == 0 {
		return 0
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return gaps[len(gaps)/2]
}

// CountAround returns how many releases fall within window on EITHER side of t
// (inclusive). The window is centered rather than backward-looking because a
// republish burst surrounds the pinned version — it may be the first, middle, or
// last release in the cluster, and a backward-only window would miss the first.
func (h *ReleaseHistory) CountAround(t time.Time, window time.Duration) int {
	start, end := t.Add(-window), t.Add(window)
	n := 0
	for _, r := range h.Releases {
		if !r.Published.Before(start) && !r.Published.After(end) {
			n++
		}
	}
	return n
}

// DefaultHalfLife is the decay half-life for the weather axis. "Recent" is a
// decay curve, not a cliff (brief §6): a compromise 90 days old carries half the
// weight of one today, rather than vanishing at an arbitrary boundary.
const DefaultHalfLife = 90 * 24 * time.Hour

// Decay returns an exponential recency multiplier in (0,1] for an event that
// happened age ago. Non-positive age yields 1.
//
// Age is QUANTIZED TO WHOLE DAYS before the curve is applied. Two reasons, both
// learned from a live run: (1) with a 90-day half-life, sub-day resolution is
// false precision — nothing meaningful changes between 09:00 and 09:01; and
// (2) deriving the value from time.Now() at full precision made two consecutive
// scans of identical data differ in the 9th decimal, breaking byte-reproducible
// output (Decision D-09). Quantizing makes a scan stable for the whole day.
func Decay(age, halfLife time.Duration) float64 {
	if age <= 0 {
		return 1
	}
	if halfLife <= 0 {
		halfLife = DefaultHalfLife
	}
	days := math.Floor(age.Hours() / 24)
	halfLifeDays := halfLife.Hours() / 24
	if halfLifeDays <= 0 {
		return 1
	}
	return math.Pow(0.5, days/halfLifeDays)
}
