package pep440

import (
	"strings"
)

// Satisfies reports whether version meets every clause of a PEP 440 specifier
// set (">=2.0,<3,!=2.5.*"), and whether the input could be evaluated at all.
//
// An unparseable version, an unknown operator, or a malformed clause yields
// (false, false). That distinction is the whole contract: an unreadable
// constraint is not an unsatisfied one, and collapsing them would quietly
// remove candidates the operator never excluded.
//
// # Pre-releases
//
// A pre-release satisfies a clause only when the specifier set itself mentions
// one. This is PEP 440's rule and it is load-bearing here: without it, presuming
// "the highest satisfying version" of a package mid-beta-cycle would pick the
// beta, and the walk would descend a tree no ordinary install produces.
func Satisfies(spec, version string) (ok, evaluable bool) {
	v := Parse(version)
	if !v.Valid {
		return false, false
	}
	clauses, ok := parseSpec(spec)
	if !ok {
		return false, false
	}
	if len(clauses) == 0 {
		return true, true // an empty specifier admits everything
	}

	if v.IsPrerelease() && !mentionsPrerelease(clauses) {
		return false, true
	}
	for _, c := range clauses {
		match, evaluable := c.match(v)
		if !evaluable {
			return false, false
		}
		if !match {
			return false, true
		}
	}
	return true, true
}

type clause struct {
	op       string
	raw      string // version text as written, for === and wildcards
	wildcard bool
	ver      Version
}

func parseSpec(spec string) ([]clause, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, true
	}
	// A bare version with no operator is not a PEP 440 specifier. Some
	// ecosystems allow it; Python does not, and inventing an implicit "=="
	// would fabricate a pin nobody wrote.
	var out []clause
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var c clause
		switch {
		case strings.HasPrefix(part, "==="):
			c.op, c.raw = "===", strings.TrimSpace(part[3:])
		case strings.HasPrefix(part, "=="):
			c.op, c.raw = "==", strings.TrimSpace(part[2:])
		case strings.HasPrefix(part, "!="):
			c.op, c.raw = "!=", strings.TrimSpace(part[2:])
		case strings.HasPrefix(part, "~="):
			c.op, c.raw = "~=", strings.TrimSpace(part[2:])
		case strings.HasPrefix(part, "<="):
			c.op, c.raw = "<=", strings.TrimSpace(part[2:])
		case strings.HasPrefix(part, ">="):
			c.op, c.raw = ">=", strings.TrimSpace(part[2:])
		case strings.HasPrefix(part, "<"):
			c.op, c.raw = "<", strings.TrimSpace(part[1:])
		case strings.HasPrefix(part, ">"):
			c.op, c.raw = ">", strings.TrimSpace(part[1:])
		default:
			return nil, false // no operator, or one this package does not read
		}
		if c.raw == "" {
			return nil, false
		}
		if strings.HasSuffix(c.raw, ".*") {
			// Wildcards are legal only for == and !=.
			if c.op != "==" && c.op != "!=" {
				return nil, false
			}
			c.wildcard = true
			c.ver = Parse(strings.TrimSuffix(c.raw, ".*"))
		} else if c.op != "===" {
			c.ver = Parse(c.raw)
		}
		if c.op != "===" && !c.ver.Valid {
			return nil, false
		}
		out = append(out, c)
	}
	return out, true
}

// mentionsPrerelease reports whether any clause names a pre-release, which is
// what "explicitly requested" means in PEP 440.
func mentionsPrerelease(cs []clause) bool {
	for _, c := range cs {
		if c.op != "===" && c.ver.Valid && c.ver.IsPrerelease() {
			return true
		}
	}
	return false
}

func (c clause) match(v Version) (ok, evaluable bool) {
	switch c.op {
	case "===":
		// Arbitrary equality: a literal string comparison, by definition.
		return strings.TrimSpace(v.Original) == c.raw, true

	case "==":
		if c.wildcard {
			return prefixMatch(v, c.ver), true
		}
		return equalIgnoringLocal(v, c.ver), true

	case "!=":
		if c.wildcard {
			return !prefixMatch(v, c.ver), true
		}
		return !equalIgnoringLocal(v, c.ver), true

	case "~=":
		// Compatible release: ~=X.Y.Z is >=X.Y.Z with ==X.Y.*. A single
		// release segment is not a legal compatible-release clause.
		if len(c.ver.Release) < 2 {
			return false, false
		}
		if Compare(v, c.ver) < 0 {
			return false, true
		}
		prefix := Version{Valid: true, Epoch: c.ver.Epoch, Release: c.ver.Release[:len(c.ver.Release)-1]}
		return prefixMatch(v, prefix), true

	case "<=":
		return Compare(v, c.ver) <= 0, true
	case ">=":
		return Compare(v, c.ver) >= 0, true

	case "<":
		// Exclusive: and a pre-release of the excluded version does not sneak
		// under the bound unless the bound is itself a pre-release.
		if Compare(v, c.ver) >= 0 {
			return false, true
		}
		if !c.ver.IsPrerelease() && v.IsPrerelease() && sameRelease(v, c.ver) {
			return false, true
		}
		return true, true

	case ">":
		// Exclusive: and a post-release of the named version is not "greater"
		// for this purpose unless the bound is itself a post-release.
		if Compare(v, c.ver) <= 0 {
			return false, true
		}
		if !c.ver.HasPost && v.HasPost && sameRelease(v, c.ver) && !v.HasPre {
			return false, true
		}
		return true, true
	}
	return false, false
}

// prefixMatch implements the ".*" form: the candidate's release segment must
// begin with the clause's release segment.
func prefixMatch(v, prefix Version) bool {
	if v.Epoch != prefix.Epoch {
		return false
	}
	if len(prefix.Release) > len(v.Release) {
		return false
	}
	for i, n := range prefix.Release {
		if v.Release[i] != n {
			return false
		}
	}
	return true
}

// equalIgnoringLocal compares two versions, ignoring the candidate's local
// segment when the specifier does not carry one (PEP 440's local-version rule).
func equalIgnoringLocal(v, want Version) bool {
	if want.Local == "" {
		v.Local = ""
	}
	return Compare(v, want) == 0
}

// sameRelease reports whether two versions share an epoch and release segment,
// differing only in pre/post/dev.
func sameRelease(a, b Version) bool {
	return a.Epoch == b.Epoch && cmpRelease(a.Release, b.Release) == 0
}
