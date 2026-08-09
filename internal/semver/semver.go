// Package semver is a minimal semantic-version parser — just enough to tell a
// patch release from a minor or major one, and to order releases.
//
// It is deliberately not a full semver range solver: dependaSNORT resolves from
// lockfiles and does not evaluate ranges (Decision D-01).
package semver

import (
	"strconv"
	"strings"
)

// Version is a parsed semantic version.
type Version struct {
	Major, Minor, Patch int
	Prerelease          string
	Valid               bool
}

// Parse parses "1.2.3", "1.2.3-beta.1", or "v1.2.3". Invalid input returns a
// Version with Valid=false rather than an error, because a registry can and
// does carry non-semver tags and that is not an exceptional condition.
func Parse(s string) Version {
	v := Version{}
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return v
	}
	// Strip build metadata, then split off prerelease.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.Prerelease = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	v.Valid = true
	return v
}

// IsPrerelease reports whether v carries a prerelease tag.
func (v Version) IsPrerelease() bool { return v.Prerelease != "" }

// Compare returns -1, 0, or 1 ordering v against o. Prerelease versions sort
// before their release counterpart. Invalid versions sort last.
func (v Version) Compare(o Version) int {
	switch {
	case !v.Valid && !o.Valid:
		return 0
	case !v.Valid:
		return 1
	case !o.Valid:
		return -1
	}
	for _, pair := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Prerelease == o.Prerelease:
		return 0
	case v.Prerelease == "":
		return 1 // release > prerelease
	case o.Prerelease == "":
		return -1
	case v.Prerelease < o.Prerelease:
		return -1
	default:
		return 1
	}
}

// Bump describes the kind of version increment between two versions.
type Bump string

const (
	BumpNone    Bump = "none"
	BumpPatch   Bump = "patch"
	BumpMinor   Bump = "minor"
	BumpMajor   Bump = "major"
	BumpUnknown Bump = "unknown"
)

// BumpKind classifies the step from prev to cur.
func BumpKind(prev, cur Version) Bump {
	if !prev.Valid || !cur.Valid {
		return BumpUnknown
	}
	switch {
	case cur.Major != prev.Major:
		return BumpMajor
	case cur.Minor != prev.Minor:
		return BumpMinor
	case cur.Patch != prev.Patch:
		return BumpPatch
	default:
		return BumpNone
	}
}
