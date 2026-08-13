package builtin

import (
	"fmt"
	"strings"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// Typosquat (VC-006) flags a package whose name is a near-miss of a popular
// package name — the classic typosquat / confusion vector. It is purely
// structural: embedded corpus + edit distance, no network.
//
// It is WARN / ADVISORY by design: name-distance alone is a low-specificity,
// guilt-by-similarity signal. It surfaces in the report but must never fail a
// build, or it becomes a warning tax.
//
// # Calibration
//
// A first run against a real 58-repo workspace produced 43 findings, ALL of them
// false positives — `preact`, `color`, `through`, `tslint`, `scapy` and friends.
// A check with a 100% FP rate is worse than no check, so the rules below exist
// specifically to kill those three failure modes. See
// vc006_realworld_test.go, which pins the exact observed output at zero.
type Typosquat struct{}

const (
	// typosquatMinLen is the shortest bare name worth scoring. Short names
	// collide by chance far too often to mean anything.
	typosquatMinLen = 5
	// typosquatDist2MinLen is the length at which a distance of 2 becomes
	// meaningful. Raised from 8 to 10 after `commands`/`commander` and
	// `password`/`passport` — unrelated words two edits apart.
	typosquatDist2MinLen = 10
	// typosquatMaxDist is the largest edit distance that can produce a finding
	// below (distance 2, and only for a long enough name). It is the ceiling
	// handed to the bounded distance function so farther comparisons abandon
	// early instead of computing a full matrix nobody reads (D-33).
	typosquatMaxDist = 2
)

// Meta implements check.Check.
func (Typosquat) Meta() check.Meta {
	return check.Meta{
		ID:              "VC-006",
		Axis:            finding.AxisWeather,
		DefaultSeverity: finding.SevMedium,
		DefaultGate:     finding.GateAdvisory,
		Description:     "package name is a near-miss (typosquat) of a popular package",
	}
}

// bareName returns the unscoped package name ("@scope/pkg" -> "pkg").
func bareName(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// isScoped reports whether an npm package name carries an @scope prefix.
func isScoped(name string) bool { return strings.HasPrefix(name, "@") }

// popularParents indexes, per node ID, whether any package that depends on it is
// itself in the popular corpus.
//
// Provenance by association: a typosquat is something a human MISTYPES into a
// manifest, so it arrives as a direct dependency. A package pulled in by an
// established package is vouched for — nobody typos their way into someone
// else's transitive tree.
func popularParents(g *graph.Graph) map[string]bool {
	vouched := map[string]bool{}
	for _, e := range g.SortedEdges() {
		if e.Type != graph.EdgeDependsOn {
			continue
		}
		from := g.Get(e.From)
		if from == nil || from.Kind != graph.KindPackage {
			continue
		}
		_, set, ok := corpusFor(from.Ecosystem)
		if !ok {
			continue
		}
		if _, popular := set[bareName(from.Name)]; popular {
			vouched[e.To] = true
		}
	}
	return vouched
}

// Run implements check.Check.
func (Typosquat) Run(ctx *check.Context) []finding.Finding {
	vouched := popularParents(ctx.Graph)

	var out []finding.Finding
	for _, n := range ctx.Graph.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		// Score only against the node's OWN ecosystem corpus. Comparing a Python
		// package against npm names would produce confident nonsense.
		corpus, corpusSet, ok := corpusFor(n.Ecosystem)
		if !ok {
			continue
		}

		// FAILURE MODE 1 — scoped packages. `@vitest/utils` is not impersonating
		// `util`: the scope is explicit provenance, published under an org that
		// either is or is not trusted. Comparing its bare name to unscoped
		// popular names produced ~20 of the 43 observed false positives.
		// (Scope-squatting — `@babeI/core` for `@babel/core` — is a genuine but
		// DIFFERENT attack that must compare scope against scope. It is not
		// covered here rather than being covered badly.)
		if isScoped(n.Name) {
			continue
		}

		bare := bareName(n.Name)
		if len(bare) < typosquatMinLen {
			continue
		}
		// An exact corpus match is the real package.
		if _, legit := corpusSet[bare]; legit {
			continue
		}
		// FAILURE MODE 2 — legitimate near-neighbours. Real, established
		// packages that genuinely sit one edit from a popular name.
		if isKnownLegitimate(n.Ecosystem, bare) {
			continue
		}
		// Vouched for by an established parent.
		if vouched[n.ID] {
			continue
		}

		// Only distance 1 and 2 below produce a finding, so comparisons are
		// bounded at 2: anything farther is reported as "farther than 2" without
		// finishing the matrix (D-33). `best` and `nearest` are identical to the
		// unbounded search for every case that emits a finding.
		best, nearest := 99, ""
		for _, pop := range corpus {
			d := osaDistanceBounded(bare, pop, typosquatMaxDist)
			if d < best {
				best, nearest = d, pop
			}
			if best == 1 {
				break
			}
		}

		var conf float64
		switch {
		case best == 1:
			conf = 0.6
		// FAILURE MODE 3 — distance 2 needs a genuinely long name to mean
		// anything, or unrelated words qualify.
		case best == 2 && len(bare) >= typosquatDist2MinLen:
			conf = 0.4
		default:
			continue
		}

		out = append(out, finding.Finding{
			CheckID:     "VC-006",
			Axis:        finding.AxisWeather,
			Severity:    finding.SevMedium,
			GateClass:   finding.GateAdvisory,
			Confidence:  conf,
			NodeID:      n.ID,
			Title:       fmt.Sprintf("possible typosquat of %q", nearest),
			Evidence:    fmt.Sprintf("%q is edit-distance %d from popular package %q", bare, best, nearest),
			Remediation: fmt.Sprintf("verify you intended %q and not %q", bare, nearest),
		})
	}
	return out
}
