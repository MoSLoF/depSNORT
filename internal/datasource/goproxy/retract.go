package goproxy

import (
	"strings"

	"ihbv.io/depsnort/internal/semver"
)

// retractSpec is one parsed `retract` directive from a go.mod: either a single
// exact version, or an inclusive [lo, hi] version range. A retracted version is
// one the module's OWN author has withdrawn — `go get -u` refuses to upgrade a
// consumer into it and `go list -m -u -retracted` flags it. It is the Go-ecosystem
// analogue of a crates.io yank or a PyPI PEP 592 yank (OPU-26): the version stays
// downloadable when a go.sum already pins it, but a fresh resolution steers away
// from it — the exact asymmetry the yank-lure exploits.
type retractSpec struct {
	exact  string // set for `retract v1.2.3`
	lo, hi string // both set for `retract [v1.1.0, v1.3.0]` (inclusive)
}

// parseRetract extracts every `retract` directive from raw go.mod text. It reads
// both the single-line form (`retract v1.0.0`, `retract [v1.0.0, v1.2.0]`) and
// the parenthesised block form (`retract ( ... )`), stripping `//` line comments
// (a retract rationale) first. It is a pure text scan — it never runs `go` (D-04)
// — and tolerates a malformed entry by skipping it rather than erroring, because a
// go.mod we cannot fully parse must degrade to "no retractions found", never fail.
func parseRetract(raw []byte) []retractSpec {
	var specs []retractSpec
	inBlock := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(stripModComment(line))
		if line == "" {
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			if s, ok := parseRetractSpec(line); ok {
				specs = append(specs, s)
			}
			continue
		}
		rest, ok := strings.CutPrefix(line, "retract")
		if !ok {
			continue
		}
		// `retract` must be a standalone token, not the prefix of some identifier —
		// require the next character to open the directive body, not continue a word.
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '(' && rest[0] != '[' {
			continue
		}
		rest = strings.TrimSpace(rest)
		if rest == "(" {
			inBlock = true
			continue
		}
		if s, ok := parseRetractSpec(rest); ok {
			specs = append(specs, s)
		}
	}
	return specs
}

// parseRetractSpec parses one retract body: `v1.0.0` or `[v1.0.0, v1.2.0]`.
func parseRetractSpec(body string) (retractSpec, bool) {
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "[") {
		inner := strings.TrimSuffix(strings.TrimPrefix(body, "["), "]")
		loRaw, hiRaw, ok := strings.Cut(inner, ",")
		if !ok {
			return retractSpec{}, false
		}
		lo, hi := unquoteModToken(loRaw), unquoteModToken(hiRaw)
		if lo == "" || hi == "" {
			return retractSpec{}, false
		}
		return retractSpec{lo: lo, hi: hi}, true
	}
	v := unquoteModToken(body)
	// A single version is one bare token; embedded whitespace means a malformed line.
	if v == "" || strings.ContainsAny(v, " \t") {
		return retractSpec{}, false
	}
	return retractSpec{exact: v}, true
}

// isRetracted reports whether version falls under any retract spec — an exact
// match, or inside an inclusive [lo, hi] range. Comparison is by semver so that
// v0.3.10 orders correctly after v0.3.9 (a lexical compare gets this wrong), the
// same ordering YankLureShape relies on. A version or bound that does not parse as
// semver is skipped rather than guessed at.
func isRetracted(version string, specs []retractSpec) bool {
	v := semver.Parse(version)
	if !v.Valid {
		return false
	}
	for _, s := range specs {
		if s.exact != "" {
			if e := semver.Parse(s.exact); e.Valid && v.Compare(e) == 0 {
				return true
			}
			continue
		}
		lo, hi := semver.Parse(s.lo), semver.Parse(s.hi)
		if lo.Valid && hi.Valid && v.Compare(lo) >= 0 && v.Compare(hi) <= 0 {
			return true
		}
	}
	return false
}

// stripModComment drops a `//` line comment (a retract rationale) from a go.mod
// line. Module versions never contain "//", so a plain first-occurrence cut is safe.
func stripModComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// unquoteModToken trims surrounding double-quotes or backticks that go.mod permits
// around a token, and surrounding whitespace.
func unquoteModToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '`' && s[len(s)-1] == '`') {
			return strings.TrimSpace(s[1 : len(s)-1])
		}
	}
	return s
}

// highestVersion returns the highest valid-semver version in the list, or "" if
// none parse. Go declares a module's retractions in its highest version's go.mod,
// so this picks the one file to read them from.
func highestVersion(versions []string) string {
	best := ""
	var bestV semver.Version
	for _, v := range versions {
		pv := semver.Parse(v)
		if !pv.Valid {
			continue
		}
		if best == "" || pv.Compare(bestV) > 0 {
			best, bestV = v, pv
		}
	}
	return best
}
