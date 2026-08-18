// Package pep440 parses and compares Python versions, and evaluates version
// specifiers against them, per PEP 440.
//
// # Why this exists
//
// internal/expand presumes a version — the highest published one satisfying the
// constraints a package's own dependents declared. Presuming needs two things
// PEP 440 defines and nothing else does: an ORDERING over Python versions, and
// a decision procedure for whether a version satisfies `>=2.0,<3`. Neither is
// semver. `1.0.post1` sorts after `1.0`, `1.0.dev1` sorts before `1.0a1`, and
// `1!2.0` outranks `99.0` — get any of that wrong and the walk presumes a
// version no installer would pick.
//
// # The one rule that governs every uncertain case
//
// Every entry point reports whether it could evaluate the input AT ALL,
// separately from the answer. An unparseable version is not "less than
// everything" and an unreadable specifier is not "unsatisfied" — treating
// either as a verdict manufactures an exclusion the operator never wrote, and
// silently shrinks the candidate set the walk presumes from. Callers that get
// evaluable=false must decline (internal/expand marks the node contested), not
// guess.
//
// This is a SUBSET by intent, not by accident: the operators PyPI packages
// actually publish, evaluated correctly, with everything else declining. A
// wider grammar that is subtly wrong is worse than a narrow one that says so.
package pep440

import (
	"strconv"
	"strings"
)

// Version is a parsed PEP 440 version.
type Version struct {
	Valid    bool
	Original string

	Epoch   int
	Release []int

	// Pre is the pre-release segment: kind is "a", "b", or "rc" after
	// normalization ("alpha"/"beta"/"c"/"pre"/"preview" fold into those).
	HasPre  bool
	PreKind string
	PreNum  int

	HasPost bool
	PostNum int

	HasDev bool
	DevNum int

	// Local is the "+abc" segment. It participates in equality and sorts after
	// the same version without one, but a specifier's local segment is ignored
	// when comparing (PEP 440: local versions are for local use).
	Local string
}

// IsPrerelease reports whether v is a pre-release or a development release.
// Both are excluded from specifier matching unless explicitly requested.
func (v Version) IsPrerelease() bool { return v.HasPre || v.HasDev }

// Parse parses a PEP 440 version. An unparseable string returns Valid=false
// rather than an error: a registry carries non-conforming tags, and that is a
// fact about the index, not an exceptional condition. Callers must check Valid
// — never treat an invalid version as ordering below everything.
func Parse(s string) Version {
	v := Version{Original: s}
	t := strings.TrimSpace(strings.ToLower(s))
	t = strings.TrimPrefix(t, "v")
	if t == "" {
		return v
	}

	// Local segment.
	if i := strings.Index(t, "+"); i >= 0 {
		v.Local = t[i+1:]
		t = t[:i]
		if v.Local == "" {
			return v
		}
	}

	// Epoch.
	if i := strings.Index(t, "!"); i >= 0 {
		n, err := strconv.Atoi(t[:i])
		if err != nil || n < 0 {
			return v
		}
		v.Epoch = n
		t = t[i+1:]
	}

	// Normalize separators so "1.0-post1", "1.0_post1", and "1.0.post1" agree.
	t = strings.NewReplacer("-", ".", "_", ".").Replace(t)

	// dev segment.
	if i := indexSegment(t, "dev"); i >= 0 {
		num, rest, ok := trailingNum(t[i+len("dev"):])
		if !ok || rest != "" {
			return v
		}
		v.HasDev, v.DevNum = true, num
		t = strings.TrimSuffix(t[:i], ".")
	}

	// post segment. Longest first so "post" is not read as the "p" of nothing.
	for _, kw := range []string{"post", "rev", "r"} {
		i := indexSegment(t, kw)
		if i < 0 {
			continue
		}
		num, rest, ok := trailingNum(t[i+len(kw):])
		if !ok || rest != "" {
			// This keyword is not what is actually here — "r" matches inside
			// "rc1" but leaves "c1" behind. Keep looking rather than declaring
			// the whole version unparseable.
			continue
		}
		v.HasPost, v.PostNum = true, num
		t = strings.TrimSuffix(t[:i], ".")
		break
	}

	// pre segment. Longest keywords first so "preview" is not read as "pre".
	for _, kw := range []string{"preview", "alpha", "beta", "pre", "rc", "a", "b", "c"} {
		i := indexSegment(t, kw)
		if i < 0 {
			continue
		}
		num, rest, ok := trailingNum(t[i+len(kw):])
		if !ok || rest != "" {
			continue
		}
		v.HasPre, v.PreNum = true, num
		switch kw {
		case "alpha", "a":
			v.PreKind = "a"
		case "beta", "b":
			v.PreKind = "b"
		default: // rc, c, pre, preview
			v.PreKind = "rc"
		}
		t = strings.TrimSuffix(t[:i], ".")
		break
	}

	// Release segment: what is left must be dot-separated non-negative ints.
	if t == "" {
		return v
	}
	for _, part := range strings.Split(t, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return v
		}
		v.Release = append(v.Release, n)
	}
	if len(v.Release) == 0 {
		return v
	}
	v.Valid = true
	return v
}

// indexSegment finds kw where a version segment may legally begin: at the
// string start, after a ".", or DIRECTLY AFTER A DIGIT.
//
// The last case is the one that matters. PEP 440 makes the separator before a
// pre/post/dev keyword optional, so "1.0a1" and "1.0.a1" are the same version.
// Requiring a "." rejected "1.0a1", "1.0rc1", and "1.0alpha1" — three of the
// most common shapes on PyPI — as unparseable, which under this package's
// decline-when-unsure contract would have silently shrunk the candidate set the
// walk presumes from.
//
// Keyword lists are searched longest-first so "alpha" is not read as "a", and
// a match that does not consume cleanly is skipped rather than fatal, so "r"
// matching inside "rc1" falls through to "rc".
func indexSegment(s, kw string) int {
	for i := 0; i+len(kw) <= len(s); i++ {
		if s[i:i+len(kw)] != kw {
			continue
		}
		if i == 0 || s[i-1] == '.' || (s[i-1] >= '0' && s[i-1] <= '9') {
			return i
		}
	}
	return -1
}

// trailingNum reads an optional integer. An absent number is 0, per PEP 440's
// implicit-zero rule ("1.0a" == "1.0a0").
func trailingNum(s string) (n int, rest string, ok bool) {
	s = strings.TrimPrefix(s, ".")
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, s, true
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, s, false
	}
	return n, s[i:], true
}

// Compare orders a against b, returning -1, 0, or 1. Both must be Valid; the
// caller checks. Ordering follows PEP 440: epoch, then release, then the
// dev/pre/release/post sequence.
func Compare(a, b Version) int {
	if c := cmpInt(a.Epoch, b.Epoch); c != 0 {
		return c
	}
	if c := cmpRelease(a.Release, b.Release); c != 0 {
		return c
	}
	if c := cmpInt(preRank(a), preRank(b)); c != 0 {
		return c
	}
	if a.HasPre && b.HasPre {
		if c := cmpInt(kindRank(a.PreKind), kindRank(b.PreKind)); c != 0 {
			return c
		}
		if c := cmpInt(a.PreNum, b.PreNum); c != 0 {
			return c
		}
	}
	// A post-release outranks the plain release; absent post sorts first.
	if c := cmpInt(postRank(a), postRank(b)); c != 0 {
		return c
	}
	// A dev release sorts BEFORE its non-dev counterpart, so absent dev is
	// highest.
	if c := cmpInt(devRank(a), devRank(b)); c != 0 {
		return c
	}
	// A local version sorts after the same version without one.
	switch {
	case a.Local == b.Local:
		return 0
	case a.Local == "":
		return -1
	case b.Local == "":
		return 1
	case a.Local < b.Local:
		return -1
	}
	return 1
}

// preRank places the pre-release phase relative to the final release.
// dev-without-pre sorts first, then pre-releases, then the release itself.
func preRank(v Version) int {
	switch {
	case v.HasPre:
		return 0
	case v.HasDev && !v.HasPost:
		return -1
	default:
		return 1
	}
}

func kindRank(k string) int {
	switch k {
	case "a":
		return 0
	case "b":
		return 1
	default:
		return 2
	}
}

func postRank(v Version) int {
	if !v.HasPost {
		return -1
	}
	return v.PostNum
}

func devRank(v Version) int {
	if !v.HasDev {
		return 1 << 30 // absent dev is the highest
	}
	return v.DevNum
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpRelease(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := cmpInt(at(a, i), at(b, i)); c != 0 {
			return c
		}
	}
	return 0
}

func at(s []int, i int) int {
	if i < len(s) {
		return s[i]
	}
	return 0 // trailing zeros are insignificant: 1.0 == 1.0.0
}
