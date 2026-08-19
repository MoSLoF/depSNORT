// Package nugetver parses and compares NuGet package versions and evaluates
// NuGet version ranges against them.
//
// # Why NuGet needs its own version model
//
// It does not fit internal/semver, and bending semver to fit would break npm
// and Cargo, which are strictly three-part. Two differences:
//
//   - FOUR components. NuGet versions are commonly "1.2.3.4" (the legacy
//     Major.Minor.Patch.Revision form), which a three-part parser rejects.
//     Rejecting them would make ordinary NuGet packages unparseable, and under
//     the walk's decline-when-unsure contract that would mark half of .NET's
//     ecosystem contested rather than presumed.
//   - INTERVAL RANGES. "[1.0,2.0)" is a half-open interval, "[1.0]" is exact,
//     "1.0" is a MINIMUM (>=1.0), not an exact match and not a caret. The
//     bracket grammar shares nothing with the operator grammar semver evaluates.
//
// # The contract, same as pep440 and the semver range evaluator
//
// Every entry point reports whether it could evaluate the input separately from
// the answer. An unparseable version or an unreadable range yields
// (false, false), and the walk marks the node contested rather than treating "I
// could not read it" as "it does not match" — which would silently drop a
// candidate the range never excluded.
package nugetver

import (
	"strconv"
	"strings"
)

// Version is a parsed NuGet version: up to four numeric components plus an
// optional prerelease label. Build metadata ("+abc") is parsed and ignored for
// ordering, per SemVer 2.0.
type Version struct {
	Valid      bool
	Parts      [4]int // Major, Minor, Patch, Revision — absent components are 0
	Prerelease string
}

// IsPrerelease reports whether v carries a prerelease label.
func (v Version) IsPrerelease() bool { return v.Prerelease != "" }

// Parse parses a NuGet version. Accepts 2-to-4 numeric components, an optional
// "-prerelease" label, and optional "+build" metadata. Invalid input returns
// Valid=false rather than an error: a feed carries non-conforming tags, and
// that is a fact about the feed, not an exception. Callers MUST check Valid.
func Parse(s string) Version {
	var v Version
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, "v")
	if t == "" {
		return v
	}
	if i := strings.IndexByte(t, '+'); i >= 0 {
		t = t[:i] // drop build metadata
	}
	if i := strings.IndexByte(t, '-'); i >= 0 {
		v.Prerelease = t[i+1:]
		t = t[:i]
		if v.Prerelease == "" {
			return v
		}
	}
	parts := strings.Split(t, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return v
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v
		}
		v.Parts[i] = n
	}
	v.Valid = true
	return v
}

// Compare orders a against b (-1, 0, 1). Both must be Valid; the caller checks.
// Numeric components first, then prerelease: a release outranks its prerelease,
// and two prereleases compare by SemVer 2.0 dot-separated identifier rules
// (numeric identifiers compare numerically, and fewer identifiers sort lower
// when all preceding ones are equal).
func Compare(a, b Version) int {
	for i := 0; i < 4; i++ {
		if c := cmpInt(a.Parts[i], b.Parts[i]); c != 0 {
			return c
		}
	}
	switch {
	case a.Prerelease == "" && b.Prerelease == "":
		return 0
	case a.Prerelease == "":
		return 1 // release > prerelease
	case b.Prerelease == "":
		return -1
	}
	return comparePrerelease(a.Prerelease, b.Prerelease)
}

func comparePrerelease(a, b string) int {
	ai, bi := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ai) && i < len(bi); i++ {
		an, aNum := toInt(ai[i])
		bn, bNum := toInt(bi[i])
		switch {
		case aNum && bNum:
			if c := cmpInt(an, bn); c != 0 {
				return c
			}
		case aNum != bNum:
			// A numeric identifier always sorts lower than an alphanumeric one.
			if aNum {
				return -1
			}
			return 1
		default:
			if c := strings.Compare(strings.ToLower(ai[i]), strings.ToLower(bi[i])); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(ai), len(bi))
}

func toInt(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
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
