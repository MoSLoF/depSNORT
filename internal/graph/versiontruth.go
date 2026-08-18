package graph

// Version truth (the expansion axis).
//
// These keys are ECOSYSTEM-NEUTRAL and live here for the same reason the
// coverage keys (D-24) and the provenance keys (D-41) do: how a version is
// known is a property of the scan's authority, and the verdict layer must read
// it without knowing which walker or registry produced it.
//
// # Why the axis exists
//
// A lockfile-only scan can treat every version as equally true, because every
// version came from a file the operator committed. The moment the graph is
// walked past what the file recorded — which it must be, or the layers worth
// hiding something in are never read — that stops holding. Some versions are
// observed, some are chosen by this tool from a constraint, and rendering them
// identically is the same error D-24 identified one axis over: a confident
// statement about something nobody looked at.
//
// An adapter records truth from what it parsed; it never decides what the
// truth level means (D-03). The verdict layer decides.
const (
	// AttrVersionTruth is how this node's version is known — one of the Truth*
	// constants. An absent value means observed: adapters that read a lockfile
	// state a fact, and requiring them all to say so would be noise.
	AttrVersionTruth = "depsnort.version_truth"
	// AttrVersionCandidates is how many published versions satisfied the
	// constraints when a version was presumed. A presumption over one candidate
	// and one over sixty are different claims, and a reader deserves to see
	// which they are looking at.
	AttrVersionCandidates = "depsnort.version_candidates"
	// AttrDeclaredConstraint is the accumulated constraint text as upstream
	// published it, recorded verbatim so a reader sees what was claimed without
	// this tool having interpreted it.
	AttrDeclaredConstraint = "depsnort.declared_constraint"
)

// Truth values for AttrVersionTruth.
const (
	// TruthObserved: a lockfile recorded this version. A fact about the build.
	TruthObserved = "observed"
	// TruthPresumed: the highest published version satisfying the accumulated
	// constraints, chosen by this tool. What an installer would most likely
	// resolve — not what one was observed to resolve.
	TruthPresumed = "presumed"
	// TruthAsserted: an external resolved-graph service supplied it. Someone
	// else's resolution, attributed rather than absorbed.
	TruthAsserted = "asserted"
	// TruthContested: the accumulated constraints admit no published version,
	// or could not be evaluated. No version is assigned.
	TruthContested = "contested"
)

// VersionTruth returns a node's truth level, defaulting to TruthObserved for a
// node that never recorded one. The default is deliberate: everything that
// predates expansion came from a lockfile, and defaulting the other way would
// retroactively demote every existing scan.
func (n *Node) VersionTruth() string {
	if n == nil || n.Attr == nil || n.Attr[AttrVersionTruth] == "" {
		return TruthObserved
	}
	return n.Attr[AttrVersionTruth]
}

// Presumed reports whether a node's version was chosen by something other than
// the operator's own lockfile — by this tool, or by a service it asked.
//
// This is the single predicate the check stage, the emitters, and the verdict
// layer share, so "was this version observed" is answered in one place. It is
// the graph.Verifiable precedent (D-41): one predicate, defined where every
// consumer can reach it, rather than a condition each caller re-derives.
func (n *Node) Presumed() bool {
	switch n.VersionTruth() {
	case TruthPresumed, TruthAsserted:
		return true
	}
	return false
}
