// Package conformance_test runs every ecosystem WalkSource through the invariants
// the Nth-layer walk (D-44) depends on but the engine cannot enforce, because
// they live in per-ecosystem code: identity normalization, range grammar, and
// version ordering.
//
// The engine has one seam per ecosystem, and each ecosystem re-implements the
// same three contracts a slightly different way — which is exactly where the
// D-15 leaks came from (a normalization applied in five places and missed in the
// sixth). One suite over all six sources turns "each adapter is supposed to do
// this" into "each adapter is TESTED to do this", so the next ecosystem cannot
// ship with a half-kept contract.
//
// Only the pure methods (Identify, Satisfies, CompareVersions, Ecosystem) are
// exercised, so the sources need no registry clients and the suite runs offline
// in `go test ./...`.
package conformance_test

import (
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/cargo"
	"ihbv.io/depsnort/internal/ecosystem/composer"
	"ihbv.io/depsnort/internal/ecosystem/gomod"
	"ihbv.io/depsnort/internal/ecosystem/npm"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/purl"
)

// source is the common surface every WalkSource satisfies. Restated here so the
// suite depends on the behaviour, not on any one struct.
type source interface {
	expand.Declarer
	expand.Presumer
}

// satCase is one range spot-check: does constraint c admit version v, and is it
// evaluable at all.
type satCase struct {
	c, v      string
	ok, evalu bool
}

// ecoCase is an ecosystem's self-description for the suite: the source under
// test, plus the per-ecosystem data the shared invariants need — what folds to
// one identity and what must not, a few range checks that exercise the
// grammar's signature quirk, and a strictly ascending version list.
type ecoCase struct {
	eco        string
	src        source
	foldSame   [][2]string // (a, b) that MUST produce the same canonical identity
	foldDiff   [][2]string // (a, b) that must NOT
	sat        []satCase
	ascending  []string // strictly increasing under CompareVersions
	lowestWins bool     // installer resolves the LOWEST satisfying version (NuGet)
}

func cases() []ecoCase {
	return []ecoCase{
		{
			eco: "pypi", src: &pypi.WalkSource{},
			foldSame:  [][2]string{{"Flask_SQLAlchemy", "flask-sqlalchemy"}, {"a.b_c", "a-b-c"}},
			foldDiff:  [][2]string{{"flask", "django"}},
			sat:       []satCase{{">=2.0", "2.5.0", true, true}, {">=2.0", "1.9", false, true}, {"^1.0", "1.0", false, false}},
			ascending: []string{"1.0", "1.0.1", "1.1", "2.0"},
		},
		{
			eco: "npm", src: &npm.WalkSource{},
			// npm is case-sensitive and has no folding.
			foldDiff:  [][2]string{{"React", "react"}, {"lodash", "Lodash"}},
			sat:       []satCase{{"^1.2.3", "1.9.0", true, true}, {"^1.2.3", "2.0.0", false, true}, {"1.2.3.4", "1.2.3", false, false}},
			ascending: []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"},
		},
		{
			eco: "cargo", src: &cargo.WalkSource{},
			// crates.io keeps `-` and `_` distinct, and is case-sensitive.
			foldDiff:  [][2]string{{"foo-bar", "foo_bar"}, {"Serde", "serde"}},
			sat:       []satCase{{"1.2.3", "1.9.0", true, true}, {"1.2.3", "2.0.0", false, true}, {"^1.x.3", "1.4.3", false, false}},
			ascending: []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"},
		},
		{
			eco: "nuget", src: &nuget.WalkSource{},
			foldSame:   [][2]string{{"Newtonsoft.Json", "newtonsoft.json"}, {"SERILOG", "serilog"}},
			sat:        []satCase{{"[1.0,2.0)", "1.5", true, true}, {"[1.0,2.0)", "2.0", false, true}, {"1.0", "1.5", true, true}},
			ascending:  []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"},
			lowestWins: true,
		},
		{
			eco: "gem", src: &rubygems.WalkSource{},
			foldDiff:  [][2]string{{"Rails", "rails"}},
			sat:       []satCase{{"~> 1.2", "1.9.0", true, true}, {"~> 1.2", "2.0.0", false, true}, {"~> 1.x", "1.2.0", false, false}},
			ascending: []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"},
		},
		{
			eco: "gomod", src: &gomod.WalkSource{},
			// Go module paths are case-sensitive and carry no scope; nothing folds.
			foldDiff:   [][2]string{{"github.com/Foo/Bar", "github.com/foo/bar"}},
			sat:        []satCase{{">=v1.2.0", "v1.5.0", true, true}, {">=v1.2.0", "v1.0.0", false, true}, {">=v1.2.0", "v2.0.0", true, true}},
			ascending:  []string{"v1.0.0", "v1.0.1", "v1.1.0", "v2.0.0"},
			lowestWins: true,
		},
		{
			eco: "composer", src: &composer.WalkSource{},
			foldSame: [][2]string{{"Monolog/Monolog", "monolog/monolog"}},
			// composer tilde is pessimistic: ~1.2 admits 1.9.0 (npm's would not).
			sat:       []satCase{{"~1.2", "1.9.0", true, true}, {"~1.2", "2.0.0", false, true}, {"dev-main", "1.0.0", false, false}},
			ascending: []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"},
		},
	}
}

// Every ecosystem the CLI expands must appear here. A new WalkSource wired into
// the scan without a conformance entry is the gap this asserts against.
func TestEveryExpandedEcosystemIsCovered(t *testing.T) {
	want := map[string]bool{"pypi": true, "npm": true, "cargo": true, "nuget": true, "gem": true, "composer": true, "gomod": true}
	for _, c := range cases() {
		if c.src.Ecosystem() != c.eco {
			t.Errorf("%s: Ecosystem() = %q, want %q", c.eco, c.src.Ecosystem(), c.eco)
		}
		delete(want, c.eco)
	}
	for eco := range want {
		t.Errorf("ecosystem %q expands in the CLI but has no conformance case", eco)
	}
}

// Identity: normalization folds what must fold and separates what must not, an
// empty name yields an empty id, and every id is a parseable PURL. This is the
// D-15 leak class, checked for all six at once.
func TestIdentityNormalization(t *testing.T) {
	for _, c := range cases() {
		t.Run(c.eco, func(t *testing.T) {
			if id, canon := c.src.Identify("", ""); id != "" || canon != "" {
				t.Errorf("Identify(\"\") = (%q,%q), want empty", id, canon)
			}
			for _, p := range c.foldSame {
				aID, aCanon := c.src.Identify(p[0], "1.0.0")
				bID, bCanon := c.src.Identify(p[1], "1.0.0")
				if aID != bID {
					t.Errorf("%q and %q must fold to one PURL: got %q vs %q", p[0], p[1], aID, bID)
				}
				// The canonical NAME must fold too: the walk keys its per-root
				// match map on it (Identify(n.Name, "")), so a canonical that
				// does not normalize re-opens the D-15 dedupe leak even when the
				// PURL happens to normalize downstream.
				if aCanon != bCanon {
					t.Errorf("%q and %q must fold to one canonical name: got %q vs %q", p[0], p[1], aCanon, bCanon)
				}
			}
			for _, p := range c.foldDiff {
				a, _ := c.src.Identify(p[0], "1.0.0")
				b, _ := c.src.Identify(p[1], "1.0.0")
				if a == b {
					t.Errorf("%q and %q must stay distinct identities, both became %q", p[0], p[1], a)
				}
			}
			// Every produced id parses back as a PURL.
			id, _ := c.src.Identify("some-package", "1.2.3")
			if _, err := purl.Parse(id); err != nil {
				t.Errorf("Identify produced an unparseable PURL %q: %v", id, err)
			}
			// Determinism.
			id2, _ := c.src.Identify("some-package", "1.2.3")
			if id != id2 {
				t.Errorf("Identify not deterministic: %q vs %q", id, id2)
			}
		})
	}
}

// Range grammar: the spot-checks pass, and — the load-bearing contract — an
// unreadable constraint DECLINES (evaluable=false) rather than silently
// answering, so the walk marks a node contested instead of dropping a candidate
// the grammar never excluded.
func TestRangeGrammar(t *testing.T) {
	garbage := []string{"~~~nonsense~~~", "not a constraint", "\x00\x01", "<<<>>>"}
	for _, c := range cases() {
		t.Run(c.eco, func(t *testing.T) {
			for _, s := range c.sat {
				ok, ev := c.src.Satisfies(s.c, s.v)
				if ok != s.ok || ev != s.evalu {
					t.Errorf("Satisfies(%q,%q) = (%v,%v), want (%v,%v)", s.c, s.v, ok, ev, s.ok, s.evalu)
				}
			}
			// Garbage must never panic and must decline.
			for _, gc := range garbage {
				ok, ev := c.src.Satisfies(gc, "1.0.0")
				if ev {
					t.Errorf("garbage constraint %q reported evaluable; must decline", gc)
				}
				if ok {
					t.Errorf("garbage constraint %q reported satisfied", gc)
				}
			}
			// A garbage VERSION against a real constraint also declines.
			if _, ev := c.src.Satisfies(c.sat[0].c, "not-a-version"); ev {
				t.Errorf("garbage version reported evaluable against %q", c.sat[0].c)
			}
		})
	}
}

// Version ordering is a strict total order: reflexive, antisymmetric, and
// consistent with the declared ascending list. The walk sorts candidates by
// this to pick the version an installer would resolve; a non-order would pick
// the wrong one silently.
func TestVersionOrdering(t *testing.T) {
	for _, c := range cases() {
		t.Run(c.eco, func(t *testing.T) {
			vs := c.ascending
			for i := range vs {
				if got := c.src.CompareVersions(vs[i], vs[i]); got != 0 {
					t.Errorf("CompareVersions(%q,%q) = %d, want 0 (reflexive)", vs[i], vs[i], got)
				}
			}
			for i := 0; i < len(vs); i++ {
				for j := 0; j < len(vs); j++ {
					ab := sign(c.src.CompareVersions(vs[i], vs[j]))
					ba := sign(c.src.CompareVersions(vs[j], vs[i]))
					if ab != -ba {
						t.Errorf("not antisymmetric: cmp(%q,%q)=%d cmp(%q,%q)=%d", vs[i], vs[j], ab, vs[j], vs[i], ba)
					}
					if i < j && ab != -1 {
						t.Errorf("ascending order broken: cmp(%q,%q)=%d, want -1", vs[i], vs[j], ab)
					}
				}
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// Resolution direction is a per-ecosystem contract the walk reads through the
// optional LowestResolver interface. NuGet installs the lowest satisfying
// version; the rest install the highest. A source claiming the wrong direction
// would presume a version no installer selects, so the claim is checked here
// against the ecosystem's declared expectation.
func TestResolutionDirection(t *testing.T) {
	for _, c := range cases() {
		t.Run(c.eco, func(t *testing.T) {
			lr, ok := c.src.(expand.LowestResolver)
			got := ok && lr.PrefersLowest()
			if got != c.lowestWins {
				t.Errorf("%s prefers-lowest = %v, want %v", c.eco, got, c.lowestWins)
			}
		})
	}
}
