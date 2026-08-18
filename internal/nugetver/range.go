package nugetver

import "strings"

// Satisfies reports whether version meets a NuGet version range, and whether the
// range could be evaluated at all.
//
// # The grammar
//
//	1.0        minimum: x >= 1.0        (NOT exact, NOT caret)
//	[1.0]      exact:   x == 1.0
//	[1.0,)     x >= 1.0
//	(1.0,)     x > 1.0
//	(,1.0]     x <= 1.0
//	(,1.0)     x < 1.0
//	[1.0,2.0]  1.0 <= x <= 2.0
//	(1.0,2.0)  1.0 <  x <  2.0
//	[1.0,2.0)  1.0 <= x <  2.0
//	(empty)    any
//
// A bare version being a MINIMUM, not an exact pin, is the difference that
// matters most: reading "1.0" as "==1.0" would exclude every serviced patch a
// real restore would accept.
//
// # Pre-releases
//
// A pre-release satisfies a range only when a bound in the range is itself a
// pre-release — the same rule NuGet's own resolver applies, and the same one
// pep440 and the semver evaluator keep. Without it, presuming "the applicable
// version" of a package mid-preview would pick the preview.
func Satisfies(rangeExpr, version string) (ok, evaluable bool) {
	v := Parse(version)
	if !v.Valid {
		return false, false
	}
	expr := strings.TrimSpace(rangeExpr)
	if expr == "" || expr == "*" {
		return !v.IsPrerelease(), true
	}

	lo, hi, loInc, hiInc, exact, ok := parseRange(expr)
	if !ok {
		return false, false
	}

	// The pre-release rule: allow a prerelease candidate only when a bound names
	// one. Any explicit bound in the range that is a prerelease opts them in.
	if v.IsPrerelease() {
		boundPre := (lo != nil && lo.IsPrerelease()) || (hi != nil && hi.IsPrerelease())
		if !boundPre {
			return false, true
		}
	}

	if exact != nil {
		return Compare(v, *exact) == 0, true
	}
	if lo != nil {
		c := Compare(v, *lo)
		if c < 0 || (c == 0 && !loInc) {
			return false, true
		}
	}
	if hi != nil {
		c := Compare(v, *hi)
		if c > 0 || (c == 0 && !hiInc) {
			return false, true
		}
	}
	return true, true
}

// parseRange decodes the grammar into optional lower/upper bounds and their
// inclusivity, or an exact version. ok is false for anything malformed.
func parseRange(expr string) (lo, hi *Version, loInc, hiInc bool, exact *Version, ok bool) {
	// Bare version -> minimum bound, inclusive.
	if !strings.HasPrefix(expr, "[") && !strings.HasPrefix(expr, "(") {
		v := Parse(expr)
		if !v.Valid {
			return nil, nil, false, false, nil, false
		}
		return &v, nil, true, false, nil, true
	}

	if len(expr) < 2 {
		return nil, nil, false, false, nil, false
	}
	open, close := expr[0], expr[len(expr)-1]
	if (open != '[' && open != '(') || (close != ']' && close != ')') {
		return nil, nil, false, false, nil, false
	}
	inner := expr[1 : len(expr)-1]

	// No comma: exact "[1.0]" (only brackets denote exact; "(1.0)" is empty and
	// invalid).
	if !strings.Contains(inner, ",") {
		if open != '[' || close != ']' {
			return nil, nil, false, false, nil, false
		}
		v := Parse(strings.TrimSpace(inner))
		if !v.Valid {
			return nil, nil, false, false, nil, false
		}
		return nil, nil, false, false, &v, true
	}

	parts := strings.SplitN(inner, ",", 2)
	loStr, hiStr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if loStr != "" {
		v := Parse(loStr)
		if !v.Valid {
			return nil, nil, false, false, nil, false
		}
		lo = &v
	}
	if hiStr != "" {
		v := Parse(hiStr)
		if !v.Valid {
			return nil, nil, false, false, nil, false
		}
		hi = &v
	}
	if lo == nil && hi == nil {
		return nil, nil, false, false, nil, false // "(,)" is meaningless
	}
	return lo, hi, open == '[', close == ']', nil, true
}
