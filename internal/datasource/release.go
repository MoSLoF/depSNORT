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

// Publisher is the identity that published one specific version.
//
// This is deliberately distinct from ReleaseHistory.Maintainers, which is a
// CURRENT package-level list. A maintainer list answers "who can publish this
// package today?" and cannot answer "who published version N versus N+1?" —
// and the second question is the one that matters when an account is taken
// over: the maintainer list looks identical before and after a stolen token
// pushes a release (Decision D-40).
type Publisher struct {
	// ID is the registry's stable identifier where one exists, else the login.
	ID string `json:"id,omitempty"`
	// Name is the human-readable login/username.
	Name string `json:"name,omitempty"`
	// Email is recorded only when the registry publishes it.
	Email string `json:"email,omitempty"`
	// Source names WHERE this identity came from ("npm._npmUser",
	// "crates.published_by") — provenance of the provenance, so a reader can
	// tell a registry-asserted identity from an inferred one.
	Source string `json:"source,omitempty"`
}

// IsZero reports whether no publisher identity was recorded. Callers must treat
// this as "unknown", never as "unchanged".
func (p Publisher) IsZero() bool { return p == Publisher{} }

// Key is the identity used to compare publishers across versions. The registry
// ID is preferred because logins can be renamed and reused; the login is the
// fallback for registries that expose no stable ID.
func (p Publisher) Key() string {
	if p.ID != "" {
		return p.ID
	}
	return p.Name
}

// ReleaseHistory is a package's publish timeline — the substrate of the
// temporal ("recent-compromise weather") axis. A lockfile pins exactly one
// version and carries no history, so this can only come from a registry.
type ReleaseHistory struct {
	Package     string    `json:"package"`
	Ecosystem   string    `json:"ecosystem"`
	Releases    []Release `json:"releases"` // sorted oldest -> newest
	Maintainers []string  `json:"maintainers,omitempty"`
	// Publishers maps version -> the identity that published it, where the
	// registry exposes per-version provenance (npm and crates.io do; the other
	// four do not). An absent entry is a coverage fact, not a claim of
	// continuity.
	Publishers map[string]Publisher `json:"publishers,omitempty"`
	// Hooks maps version -> the install-time lifecycle hook names that version
	// DECLARES, where registry metadata carries the manifest (npm's packument
	// embeds each version's package.json). This is the one drift signal
	// available without a baseline file, because it needs no artifact download.
	Hooks map[string][]string `json:"hooks,omitempty"`
}

// PublisherAt returns the identity that published version, when known.
func (h *ReleaseHistory) PublisherAt(version string) (Publisher, bool) {
	if h == nil || len(h.Publishers) == 0 {
		return Publisher{}, false
	}
	p, ok := h.Publishers[version]
	if !ok || p.IsZero() {
		return Publisher{}, false
	}
	return p, true
}

// PriorPublisherSet is what is known about who published the releases BEFORE a
// given version.
//
// Recorded and Unrecorded are tracked separately because the difference decides
// what may be claimed (finding DS-REV-04). "This publisher appears in none of
// the prior releases we can see" and "this publisher has never published this
// package" are different statements, and only the second justifies escalating.
type PriorPublisherSet struct {
	// Keys is the set of publisher identities observed before the version.
	Keys map[string]bool
	// Recorded counts prior releases that carry a publisher identity.
	Recorded int
	// Unrecorded counts prior releases that do not. On crates.io this is
	// routinely most of a package's history — published_by postdates many
	// releases — so treating it as zero would make the strongest claim exactly
	// where the evidence is thinnest.
	Unrecorded int
}

// Evaluable reports whether any prior publisher is known at all. With none, no
// statement about this publisher's history can be made.
func (s PriorPublisherSet) Evaluable() bool { return s.Recorded > 0 }

// Complete reports whether EVERY prior release carries a publisher identity.
// Only then does "not among the prior publishers" mean "never published this
// package before".
func (s PriorPublisherSet) Complete() bool { return s.Recorded > 0 && s.Unrecorded == 0 }

// Seen reports whether key published one of the prior releases.
func (s PriorPublisherSet) Seen(key string) bool { return s.Keys[key] }

// PriorPublishers returns what is known about publishers of the releases
// strictly before version.
//
// This is what keeps VC-011 honest. A package whose earlier releases carry no
// publisher data cannot support the claim "this publisher is new" — and a
// package whose history is PARTIALLY recorded cannot either, because the
// publisher in question may be sitting in one of the gaps.
func (h *ReleaseHistory) PriorPublishers(version string) PriorPublisherSet {
	out := PriorPublisherSet{Keys: map[string]bool{}}
	if h == nil {
		return out
	}
	idx := h.IndexOf(version)
	if idx < 0 {
		return out
	}
	for _, r := range h.Releases[:idx] {
		if p, ok := h.Publishers[r.Version]; ok && !p.IsZero() {
			out.Keys[p.Key()] = true
			out.Recorded++
			continue
		}
		out.Unrecorded++
	}
	return out
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
