package graph

import "strings"

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

// AttrDeclaredDeps carries a root's DIRECT dependencies that a manifest declared
// but no lockfile pinned — an unpinned requirements.txt line, a pyproject
// [project] entry. Each is a name and a raw constraint with no version, encoded
// as "name\tconstraint" per line (constraint may be empty). It is the seam that
// lets transitive expansion presume versions for a manifest-only project: the
// declarations come from the local file (not a registry, which has no record of
// the local root), so the adapter records them here for the walk to read.
//
// This is distinct from AttrUnresolved, which is the human-facing coverage
// disclosure ("these were not pinned"). Both can be present: the deps are
// disclosed as unpinned AND made available for presumption.
const AttrDeclaredDeps = "depsnort.declared_deps"

// DeclaredDep is one manifest-declared direct dependency without a version.
type DeclaredDep struct {
	Name       string
	Constraint string
}

// EncodeDeclaredDeps renders declared deps for AttrDeclaredDeps. Deterministic:
// entries are emitted in the order given, and a name containing a tab or
// newline is skipped rather than corrupting the encoding (no real package name
// contains either).
func EncodeDeclaredDeps(deps []DeclaredDep) string {
	var b strings.Builder
	for _, d := range deps {
		if d.Name == "" || strings.ContainsAny(d.Name, "\t\n") || strings.ContainsRune(d.Constraint, '\n') {
			continue
		}
		b.WriteString(d.Name)
		b.WriteByte('\t')
		b.WriteString(d.Constraint)
		b.WriteByte('\n')
	}
	return b.String()
}

// DecodeDeclaredDeps parses what EncodeDeclaredDeps wrote.
func DecodeDeclaredDeps(s string) []DeclaredDep {
	var out []DeclaredDep
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		name, constraint, _ := strings.Cut(line, "\t")
		if name != "" {
			out = append(out, DeclaredDep{Name: name, Constraint: constraint})
		}
	}
	return out
}

// DeclaredDepsOf returns a node's manifest-declared direct dependencies.
func (n *Node) DeclaredDepsOf() []DeclaredDep {
	if n == nil || n.Attr == nil {
		return nil
	}
	return DecodeDeclaredDeps(n.Attr[AttrDeclaredDeps])
}
