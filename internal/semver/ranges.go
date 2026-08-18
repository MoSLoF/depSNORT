package semver

import "strings"

// Range evaluation for npm-style semver.
//
// # Why this is here now, when the package said it would not be
//
// The package doc declares depSNORT resolves from lockfiles and does not
// evaluate ranges (D-01). That held while every version in the graph came from
// a lockfile. The Nth-layer walk (D-44) breaks that premise on purpose: it
// reads a package's declared dependencies, which are RANGES ("^1.2.0"), and
// must pick the highest published version each admits. That is range
// evaluation, and it lives here beside the comparator it reuses.
//
// It is NOT a resolver. It answers one closed question — does this concrete
// version satisfy this range — with no backtracking and no conflict search. The
// walk does the picking; this only judges.
//
// # The contract every entry point keeps
//
// evaluable is reported separately from the answer. A range this subset does
// not understand yields (false, false), and the walk marks the node contested
// rather than treating "I could not read it" as "it does not match" — which
// would silently drop a candidate the operator never excluded. The grammar
// covered is the one npm packages actually publish: exact, the comparators,
// caret, tilde, x-ranges, hyphen ranges, AND (space), and OR (||). Anything
// else declines.

// Satisfies reports whether version meets an npm range expression, and whether
// the range could be evaluated at all.
func Satisfies(rangeExpr, version string) (ok, evaluable bool) {
	v := Parse(version)
	if !v.Valid {
		return false, false
	}
	expr := strings.TrimSpace(rangeExpr)
	if expr == "" || expr == "*" || expr == "x" || expr == "X" {
		// The empty range and the wildcard admit everything EXCEPT a
		// pre-release, which npm withholds unless a comparator names one.
		return !v.IsPrerelease(), true
	}

	// OR splits into alternatives; the version satisfies the range if it
	// satisfies any one of them.
	for _, alt := range strings.Split(expr, "||") {
		set, ok := parseComparatorSet(alt)
		if !ok {
			return false, false
		}
		if satisfiesSet(v, set) {
			return true, true
		}
	}
	return false, true
}

// comparator is one bound: an operator and the version it bounds.
type comparator struct {
	op string // "<", "<=", ">", ">=", "="
	v  Version
}

// parseComparatorSet turns one OR-alternative — a space-separated conjunction,
// possibly a hyphen range or an x-range or a caret/tilde — into concrete
// comparators. ok is false when any token is a shape this subset does not read.
func parseComparatorSet(alt string) (set []comparator, ok bool) {
	alt = strings.TrimSpace(alt)
	if alt == "" || alt == "*" || alt == "x" || alt == "X" {
		return nil, true // empty conjunction: any version
	}

	// Hyphen range: "1.2.3 - 2.3.4" (spaces around the hyphen are required by
	// npm, which is what lets us tell it from a "-prerelease" tag).
	if i := strings.Index(alt, " - "); i >= 0 {
		lo, hi := strings.TrimSpace(alt[:i]), strings.TrimSpace(alt[i+3:])
		loC, ok1 := hyphenLow(lo)
		hiC, ok2 := hyphenHigh(hi)
		if !ok1 || !ok2 {
			return nil, false
		}
		return append(loC, hiC...), true
	}

	for _, tok := range strings.Fields(alt) {
		cs, ok := parseToken(tok)
		if !ok {
			return nil, false
		}
		set = append(set, cs...)
	}
	return set, true
}

// parseToken expands one range token into comparators.
func parseToken(tok string) ([]comparator, bool) {
	switch {
	case strings.HasPrefix(tok, "^"):
		return caret(tok[1:])
	case strings.HasPrefix(tok, "~"):
		return tilde(tok[1:])
	case strings.HasPrefix(tok, ">="):
		return simple(">=", tok[2:])
	case strings.HasPrefix(tok, "<="):
		return simple("<=", tok[2:])
	case strings.HasPrefix(tok, ">"):
		return simple(">", tok[1:])
	case strings.HasPrefix(tok, "<"):
		return simple("<", tok[1:])
	case strings.HasPrefix(tok, "="):
		return xrange(tok[1:])
	default:
		// A bare version or an x-range: "1.2.3", "1.2.x", "1.x".
		return xrange(tok)
	}
}

// simple builds one comparator from an operator and a (possibly partial)
// version. A partial version on a comparator is completed with zeros, npm's
// rule (">=1" means ">=1.0.0").
func simple(op, raw string) ([]comparator, bool) {
	v, ok := parsePartial(raw)
	if !ok {
		return nil, false
	}
	return []comparator{{op: op, v: v}}, true
}

// xrange handles an exact version or an x-range ("1.2.x", "1.x", "1.2.3").
func xrange(raw string) ([]comparator, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "v"))
	if raw == "" || raw == "*" {
		return nil, true
	}
	major, minor, patch, hasMinor, hasPatch, ok := splitParts(raw)
	if !ok {
		return nil, false
	}
	switch {
	case !hasMinor:
		// "1" or "1.x" -> >=1.0.0 <2.0.0
		return bounded(major, 0, 0, major+1, 0, 0), true
	case !hasPatch:
		// "1.2" or "1.2.x" -> >=1.2.0 <1.3.0
		return bounded(major, minor, 0, major, minor+1, 0), true
	default:
		return []comparator{{op: "=", v: Version{Major: major, Minor: minor, Patch: patch, Valid: true}}}, true
	}
}

// caret allows changes that do not modify the left-most non-zero component:
// ^1.2.3 -> >=1.2.3 <2.0.0, ^0.2.3 -> >=0.2.3 <0.3.0, ^0.0.3 -> >=0.0.3 <0.0.4.
func caret(raw string) ([]comparator, bool) {
	major, minor, patch, hasMinor, hasPatch, ok := splitParts(strings.TrimPrefix(raw, "v"))
	if !ok {
		return nil, false
	}
	lo := Version{Major: major, Minor: minor, Patch: patch, Valid: true}
	var hi Version
	switch {
	case major > 0 || !hasMinor:
		hi = Version{Major: major + 1, Valid: true}
	case minor > 0 || !hasPatch:
		hi = Version{Major: major, Minor: minor + 1, Valid: true}
	default:
		hi = Version{Major: major, Minor: minor, Patch: patch + 1, Valid: true}
	}
	return []comparator{{">=", lo}, {"<", hi}}, true
}

// tilde allows patch-level changes if a minor version is specified, minor-level
// changes if it is not: ~1.2.3 -> >=1.2.3 <1.3.0, ~1 -> >=1.0.0 <2.0.0.
func tilde(raw string) ([]comparator, bool) {
	major, minor, patch, hasMinor, _, ok := splitParts(strings.TrimPrefix(raw, "v"))
	if !ok {
		return nil, false
	}
	lo := Version{Major: major, Minor: minor, Patch: patch, Valid: true}
	var hi Version
	if hasMinor {
		hi = Version{Major: major, Minor: minor + 1, Valid: true}
	} else {
		hi = Version{Major: major + 1, Valid: true}
	}
	return []comparator{{">=", lo}, {"<", hi}}, true
}

func hyphenLow(raw string) ([]comparator, bool) {
	v, ok := parsePartial(raw)
	if !ok {
		return nil, false
	}
	return []comparator{{">=", v}}, true
}

// hyphenHigh: a partial upper bound is inclusive of the whole partial range —
// "1.2.3 - 2.3" means <2.4.0, "1.2.3 - 2" means <3.0.0.
func hyphenHigh(raw string) ([]comparator, bool) {
	major, minor, _, hasMinor, hasPatch, ok := splitParts(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if !ok {
		return nil, false
	}
	switch {
	case !hasMinor:
		return []comparator{{"<", Version{Major: major + 1, Valid: true}}}, true
	case !hasPatch:
		return []comparator{{"<", Version{Major: major, Minor: minor + 1, Valid: true}}}, true
	default:
		v, _ := parsePartial(raw)
		return []comparator{{"<=", v}}, true
	}
}

func bounded(loMaj, loMin, loPat, hiMaj, hiMin, hiPat int) []comparator {
	return []comparator{
		{">=", Version{Major: loMaj, Minor: loMin, Patch: loPat, Valid: true}},
		{"<", Version{Major: hiMaj, Minor: hiMin, Patch: hiPat, Valid: true}},
	}
}

// parsePartial parses a version that may omit minor/patch, completing with
// zeros. Used for comparator right-hand sides, where "1.2" means "1.2.0". It
// PRESERVES a prerelease tag, unlike the bound arithmetic in caret/tilde/xrange
// which strips it — a comparator like ">=1.5.0-alpha" must keep the tag, or the
// pre-release rule can never see a bound that opts pre-releases in.
func parsePartial(raw string) (Version, bool) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	var pre string
	if i := strings.IndexByte(raw, '+'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '-'); i >= 0 {
		pre, raw = raw[i+1:], raw[:i]
	}
	major, minor, patch, _, _, ok := splitParts(raw)
	if !ok {
		return Version{}, false
	}
	return Version{Major: major, Minor: minor, Patch: patch, Prerelease: pre, Valid: true}, true
}

// splitParts parses up to three dot-separated numeric components, reporting
// which were present. An "x", "X", or "*" component is treated as absent, which
// is what makes "1.2.x" and "1.2" the same range. A prerelease tag on a full
// version is tolerated but ignored for bound arithmetic.
func splitParts(raw string) (major, minor, patch int, hasMinor, hasPatch, ok bool) {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '+'); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '-'); i >= 0 {
		raw = raw[:i] // drop prerelease for bound math
	}
	if raw == "" {
		return 0, 0, 0, false, false, false
	}
	parts := strings.Split(raw, ".")
	if len(parts) > 3 {
		return 0, 0, 0, false, false, false
	}
	vals := [3]int{}
	present := [3]bool{}
	for i, p := range parts {
		if p == "x" || p == "X" || p == "*" || p == "" {
			continue // wildcard component: leave absent
		}
		n, err := atoiNonNeg(p)
		if err {
			return 0, 0, 0, false, false, false
		}
		vals[i], present[i] = n, true
	}
	// A wildcard cannot precede a concrete component ("1.x.3" is not valid).
	if (!present[1] && present[2]) || (!present[0] && (present[1] || present[2])) {
		return 0, 0, 0, false, false, false
	}
	return vals[0], vals[1], vals[2], present[1], present[2], true
}

func atoiNonNeg(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, true
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, false
}

// satisfiesSet reports whether v meets every comparator in the conjunction, with
// npm's pre-release rule: a pre-release version matches only when some
// comparator in this set names a pre-release at the SAME [major,minor,patch].
func satisfiesSet(v Version, set []comparator) bool {
	if len(set) == 0 {
		return !v.IsPrerelease() // the "any" conjunction still excludes prereleases
	}
	if v.IsPrerelease() && !setAllowsPrerelease(v, set) {
		return false
	}
	for _, c := range set {
		if !c.matches(v) {
			return false
		}
	}
	return true
}

func setAllowsPrerelease(v Version, set []comparator) bool {
	for _, c := range set {
		if c.v.IsPrerelease() && c.v.Major == v.Major && c.v.Minor == v.Minor && c.v.Patch == v.Patch {
			return true
		}
	}
	return false
}

func (c comparator) matches(v Version) bool {
	cmp := v.Compare(c.v)
	switch c.op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=":
		return cmp == 0
	}
	return false
}

// SatisfiesCargo evaluates a Cargo (crates.io) version requirement. Cargo's
// grammar shares npm's comparators, caret, and tilde, but differs in two ways
// that change the answer:
//
//   - A BARE version is a caret requirement, not an exact match: "1.2.3" means
//     "^1.2.3". Treating it as "=1.2.3" the way npm does would exclude every
//     compatible newer release and make the walk descend a version no Cargo
//     build would select.
//   - AND is a COMMA, not a space: ">=1.2, <1.5". Cargo has no "||" OR.
//
// The caret arithmetic itself is identical to npm's, including the 0.x rules
// (^0.2.3 -> <0.3.0, ^0.0.3 -> <0.0.4), so those helpers are shared. The
// evaluable-separate-from-answer contract is the same: an unreadable
// requirement declines rather than excluding a candidate.
func SatisfiesCargo(req, version string) (ok, evaluable bool) {
	v := Parse(version)
	if !v.Valid {
		return false, false
	}
	req = strings.TrimSpace(req)
	if req == "" || req == "*" {
		return !v.IsPrerelease(), true
	}

	var set []comparator
	for _, tok := range strings.Split(req, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		cs, ok := parseCargoToken(tok)
		if !ok {
			return false, false
		}
		set = append(set, cs...)
	}
	return satisfiesSet(v, set), true
}

// parseCargoToken differs from parseToken only in the default: a token with no
// operator is a caret requirement, Cargo's rule, where npm reads it as an exact
// version or x-range.
func parseCargoToken(tok string) ([]comparator, bool) {
	switch {
	case strings.HasPrefix(tok, "^"):
		return caret(tok[1:])
	case strings.HasPrefix(tok, "~"):
		return tilde(tok[1:])
	case strings.HasPrefix(tok, ">="):
		return simple(">=", tok[2:])
	case strings.HasPrefix(tok, "<="):
		return simple("<=", tok[2:])
	case strings.HasPrefix(tok, ">"):
		return simple(">", tok[1:])
	case strings.HasPrefix(tok, "<"):
		return simple("<", tok[1:])
	case strings.HasPrefix(tok, "="):
		return xrange(tok[1:]) // "=1.2" is exact-ish; xrange handles the partial
	case strings.ContainsAny(tok, "*xX") && strings.Contains(tok, "."):
		return xrange(tok) // an explicit wildcard stays a wildcard, not a caret
	default:
		return caret(tok) // BARE VERSION IS CARET — the Cargo default
	}
}
