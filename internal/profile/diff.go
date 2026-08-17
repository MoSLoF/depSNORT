package profile

import (
	"sort"

	"ihbv.io/depsnort/internal/semver"
)

// Drift is what changed between two profiles of the same package.
//
// It is pure set arithmetic. Nothing here decides whether a change is
// suspicious — a major release that adds network access is ordinary, the same
// addition in a patch release is not, and only a check knows which policy
// applies (Decision D-03, D-40). VC-010 does the judging.
type Drift struct {
	PURL string `json:"purl"`
	From string `json:"from"`
	To   string `json:"to"`
	// Bump is the semantic distance between the two versions. The single most
	// important weight on any capability addition: a package's own version
	// number is a claim about how much should have changed.
	Bump semver.Bump `json:"bump"`

	AddedCaps   []string `json:"added_caps,omitempty"`
	RemovedCaps []string `json:"removed_caps,omitempty"`
	AddedHooks  []string `json:"added_hooks,omitempty"`
	// RemovedHooks is reported for completeness. A package DROPPING an install
	// hook is not a risk, but it is a fact a reviewer comparing two releases
	// will want to see rather than have silently filtered.
	RemovedHooks     []string `json:"removed_hooks,omitempty"`
	AddedRemoteHosts []string `json:"added_remote_hosts,omitempty"`
	AddedSinks       []string `json:"added_sinks,omitempty"`

	// PublisherChanged is true only when BOTH sides carry an identity and the
	// two differ. Missing data on either side is not a change (see
	// PublisherUnknown).
	PublisherChanged bool   `json:"publisher_changed,omitempty"`
	FromPublisher    string `json:"from_publisher,omitempty"`
	ToPublisher      string `json:"to_publisher,omitempty"`
	// PublisherUnknown is true when at least one side has no publisher
	// identity, so the actor axis could not be evaluated at all.
	PublisherUnknown bool `json:"publisher_unknown,omitempty"`

	// SourceClassChanged fires when a package that used to come from a
	// registry now comes from a git URL or a local path, or vice versa. A
	// dependency quietly repointed at a fork is a supply-chain event even when
	// its capabilities are identical.
	SourceClassChanged bool   `json:"source_class_changed,omitempty"`
	FromSourceClass    string `json:"from_source_class,omitempty"`
	ToSourceClass      string `json:"to_source_class,omitempty"`

	// TopologyChanged reports that the set of direct dependencies differs.
	TopologyChanged bool `json:"topology_changed,omitempty"`

	// Unobservable carries every reason either side is a lower bound. A diff
	// over an unread install surface can only ever report the additions it
	// happened to see, and a check must be able to say so instead of implying
	// the delta is complete.
	Unobservable []string `json:"unobservable,omitempty"`
}

// HasChange reports whether anything at all differs. Used by callers to skip
// the overwhelmingly common no-change case before doing any further work.
func (d Drift) HasChange() bool {
	return len(d.AddedCaps) > 0 || len(d.RemovedCaps) > 0 ||
		len(d.AddedHooks) > 0 || len(d.RemovedHooks) > 0 ||
		len(d.AddedRemoteHosts) > 0 || len(d.AddedSinks) > 0 ||
		d.PublisherChanged || d.SourceClassChanged || d.TopologyChanged
}

// Escalating reports whether the drift ADDS attack surface, as opposed to
// removing it or merely rearranging dependencies. A release that drops a hook
// and rewires its tree has drifted, but not in a direction worth an operator's
// attention.
func (d Drift) Escalating() bool {
	return len(d.AddedCaps) > 0 || len(d.AddedHooks) > 0 ||
		len(d.AddedRemoteHosts) > 0 || len(d.AddedSinks) > 0
}

// Diff computes the state transition from base to candidate.
//
// Both sides are expected to be profiles of the SAME package; diffing across
// packages is a caller error and produces a Drift whose PURL is the
// candidate's, which is the only sensible thing it could report.
func Diff(base, candidate Profile) Drift {
	d := Drift{
		PURL: candidate.PURL,
		From: base.Version,
		To:   candidate.Version,
		Bump: semver.BumpKind(semver.Parse(base.Version), semver.Parse(candidate.Version)),

		AddedCaps:        added(base.Caps, candidate.Caps),
		RemovedCaps:      added(candidate.Caps, base.Caps),
		AddedHooks:       added(base.Hooks, candidate.Hooks),
		RemovedHooks:     added(candidate.Hooks, base.Hooks),
		AddedRemoteHosts: added(base.RemoteHosts, candidate.RemoteHosts),
		AddedSinks:       added(base.Sinks, candidate.Sinks),

		TopologyChanged: base.TopologyDigest != candidate.TopologyDigest,
	}

	switch {
	case base.Publisher.IsZero() || candidate.Publisher.IsZero():
		// One side is unknown. Not a change, not a non-change — unevaluable,
		// and the check must be able to tell the difference (D-40).
		d.PublisherUnknown = true
	case base.Publisher.Key() != candidate.Publisher.Key():
		d.PublisherChanged = true
	}
	if !base.Publisher.IsZero() {
		d.FromPublisher = base.Publisher.Key()
	}
	if !candidate.Publisher.IsZero() {
		d.ToPublisher = candidate.Publisher.Key()
	}

	if base.SourceClass != "" && candidate.SourceClass != "" &&
		base.SourceClass != candidate.SourceClass {
		d.SourceClassChanged = true
		d.FromSourceClass = base.SourceClass
		d.ToSourceClass = candidate.SourceClass
	}

	d.Unobservable = union(base.Unobserved, candidate.Unobserved)
	return d
}

// added returns the members of b that are absent from a, sorted.
func added(a, b []string) []string {
	if len(b) == 0 {
		return nil
	}
	have := make(map[string]bool, len(a))
	for _, v := range a {
		have[v] = true
	}
	var out []string
	for _, v := range b {
		if !have[v] {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func union(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	set := make(map[string]bool, len(a)+len(b))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		set[v] = true
	}
	return sortedKeys(set)
}
