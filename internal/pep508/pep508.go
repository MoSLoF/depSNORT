// Package pep508 implements the minimal subset of PEP 508 (Python dependency
// specifiers) that depSNORT needs: splitting a requirement string into its
// name/version/marker parts, and judging whether a marker proves a
// dependency is platform-gated. It has no dependency on any ecosystem
// adapter so both internal/datasource/registry (which fetches PyPI
// `requires_dist` metadata) and internal/installsurface (which reads
// `build-system.requires` out of pyproject.toml) can import it without
// creating an import cycle through internal/ecosystem/pypi.
package pep508

import (
	"regexp"
	"strings"
)

// utf8BOM is the UTF-8 encoding of U+FEFF. strings.TrimSpace does NOT remove
// it — U+FEFF is Unicode category Cf, not White_Space — so a requirements.txt
// written by `pip freeze` under Windows PowerShell 5.1 (or saved by Notepad)
// carries it on the first line and would otherwise fail the anchored name
// match, silently dropping that dependency.
const utf8BOM = "\uFEFF"

// nameAndExtrasRe matches a PEP 508 distribution name plus an optional extras
// group, ANCHORED AT THE START of the requirement. Submatch 1 is the bare name.
// The grammar is PEP 508's own: a name starts and ends with an alphanumeric,
// with '-', '_' and '.' permitted only in the interior.
var nameAndExtrasRe = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?`)

// versionRe bounds what may be accepted as an exact pinned version. It is
// deliberately permissive about PEP 440's internal structure (epochs, pre/post/
// dev segments, local versions) but strict about the character set, because
// anything accepted here is handed to purl.NewPyPI and becomes a graph node
// identity. Without it, "foo==1.0 bar" or "foo==1.0#egg=x" would mint a node
// with a malformed PURL asserted as a confident exact pin.
var versionRe = regexp.MustCompile(`^v?[0-9][A-Za-z0-9.!+_-]*$`)

// isSpecifierStart reports whether b can legally begin what follows a PEP 508
// name+extras: a PEP 440 version specifier (every comparison operator begins
// with one of < > = ! ~) or a direct reference (@).
//
// This VALIDATES the name token's right edge; it does not scan for a delimiter.
// It never locates a split point — the anchored name grammar alone decides
// where the name ends — it only confirms the name ended at a real boundary.
// That distinction matters because it inverts the failure direction of the bug
// this parser replaced: a character missing from this set makes an entry
// UNPARSEABLE (name == "", a disclosed gap), never a corrupted name. The set is
// closed and unordered, so no priority ordering can be wrong.
//
// '(' and '[' are deliberately absent: unwrapLegacyParenSpec has already
// normalized every well-formed "name (spec)" form, and the extras group in
// nameAndExtrasRe has already consumed every well-formed "[...]", so either
// character surviving to here means the input was malformed.
func isSpecifierStart(b byte) bool {
	switch b {
	case '<', '>', '=', '!', '~', '@':
		return true
	}
	return false
}

// Split splits "name[extra]==1.2.3 ; marker" into its name, version, and PEP 508
// environment marker (if any). pinned is true only for a single, exact `==` pin.
// marker is returned verbatim (untrimmed of internal spacing beyond the outer
// TrimSpace) so it can be surfaced to the caller rather than silently discarded.
//
// The name is matched POSITIVELY and ANCHORED AT THE START using PEP 508's real
// name grammar; everything after the match is the specifier. The parser
// therefore never has to enumerate operators to find where the name ends. That
// is deliberate. The previous implementation scanned for delimiters in a fixed
// priority order, which defines a name by what it is NOT, and silently
// corrupted every name whose specifier had more than one comma-joined clause
// ("idna<4,>=2.5" -> "idna<4,") because ">=" was checked before "<" and found to
// its right. Anchored matching kills that whole bug CATEGORY, not one instance:
//
//   - extras containing commas ("foo[a,b]>=1,<2") are consumed by the pattern,
//     so an extras comma can never contaminate the compound test;
//   - a direct reference whose URL contains operator characters
//     ("foo @ git+ssh://git@host/x") is immune, because the URL is never scanned;
//   - "===" cannot be mis-read as "==";
//   - an operator nobody enumerated cannot corrupt a name.
//
// An entry that does not match returns name == "" — a VISIBLE ABSENCE that
// callers must disclose — rather than a silently corrupted name.
//
// SCOPE OF THAT GUARANTEE: name != "" means "this is grammatically a PEP 508
// name", never "this is a real distribution". A wheel filename such as
// "requests-2.31.0-py3-none-any.whl" is a grammatically valid name and is
// returned as one. Distinguishing it would require heuristics, which D-01
// forbids. Callers must not treat a non-empty name as validated identity.
//
// Version/pin rules, all conservative in the same direction (fail toward a
// disclosed gap, never toward a confident claim):
//
//   - A COMPOUND specifier (one containing ',') is a RANGE, never a pin, even
//     when one of its clauses is "==" ("foo==1.0,!=1.0.1"). Per D-01 a range is
//     refused and disclosed, never resolved to a guessed concrete version.
//   - "===" (PEP 440 arbitrary equality) is treated as UNPINNED. Deliberate
//     decision: arbitrary equality is not a version we can resolve or query, so
//     it fails toward a disclosed gap rather than minting a node from a version
//     string we invented.
//   - An accepted "==" version must satisfy versionRe. Anything else is
//     unpinned and disclosed rather than becoming a malformed node identity.
//   - A direct reference ("foo @ url") is unpinned. If such a URL happens to
//     contain a comma the compound rule fires first; the OUTCOME is right (a
//     direct reference is never a pin) even though the recorded reason reads as
//     "compound". Do not "fix" that into a pin.
//
// NOTE: "==1.0.*" is treated as a pin to "1.0". That is pre-existing
// prefix-match-as-pin behavior with a test asserting it, and is out of scope
// for this parser fix.
func Split(s string) (name, version string, pinned bool, marker string) {
	// Environment markers: "pkg==1.0 ; python_version < '3.9'"
	if i := strings.IndexByte(s, ';'); i >= 0 {
		marker = strings.TrimSpace(s[i+1:])
		s = s[:i]
	}
	// Strip a leading BOM, then trim. TrimSpace runs BEFORE
	// unwrapLegacyParenSpec because that helper tests HasSuffix(s, ")"), so
	// "foo (==1.2.3) " with one trailing space would otherwise fail to unwrap
	// and silently downgrade a real pin to a gap.
	s = strings.TrimPrefix(strings.TrimSpace(s), utf8BOM)
	s = unwrapLegacyParenSpec(strings.TrimSpace(s))

	idx := nameAndExtrasRe.FindStringSubmatchIndex(s)
	if idx == nil {
		return "", "", false, marker
	}
	// rest is sliced from the end of the FULL match (idx[1]), never the end of
	// the name submatch (idx[3]): using idx[3] would leave an extras group in
	// rest, whose comma would trip the compound rule below and silently
	// downgrade a legitimate exact pin ("foo[a,b]==1.0") to unpinned.
	name = s[idx[2]:idx[3]]
	rest := strings.TrimSpace(s[idx[1]:])

	if rest == "" {
		return name, "", false, marker
	}
	if !isSpecifierStart(rest[0]) {
		// The name did not end at a legal PEP 508 boundary, so this is not a
		// requirement at all — a bare URL, a local path, a wheel filename with a
		// trailing token, a stray separator. Disclose it as unparseable instead
		// of reporting the leading token as though it were a package name:
		// "https://files.pythonhosted.org/x/foo-1.0.tar.gz" must not become the
		// real PyPI package "https".
		return "", "", false, marker
	}
	if strings.Contains(rest, ",") {
		// Compound specifier == a range, never a pin (D-01).
		return name, "", false, marker
	}
	if strings.HasPrefix(rest, "==") && !strings.HasPrefix(rest, "===") {
		version = strings.TrimSuffix(strings.TrimSpace(rest[2:]), ".*")
		if version != "" && versionRe.MatchString(version) {
			return name, version, true, marker
		}
		return name, "", false, marker
	}
	return name, "", false, marker
}

// unwrapLegacyParenSpec normalizes PyPI JSON API's legacy PEP 345-style
// requires_dist form, "name (>=1.2.3)", to the plain PEP 508 form the rest of
// Split expects, "name >=1.2.3". requirements.txt-style callers never
// produce this shape, so it is a no-op for them. Left untouched if s doesn't
// look like "name (...)" — including a bare "(local version)" with no name
// before it, which would otherwise truncate name to empty.
func unwrapLegacyParenSpec(s string) string {
	i := strings.IndexByte(s, '(')
	if i <= 0 || !strings.HasSuffix(s, ")") {
		return s
	}
	name := strings.TrimSpace(s[:i])
	spec := strings.TrimSpace(s[i+1 : len(s)-1])
	if name == "" {
		return s
	}
	if spec == "" {
		return name
	}
	return name + " " + spec
}

// StripExtras removes an extras suffix: "requests[security]" -> "requests".
//
// Split no longer calls this — nameAndExtrasRe consumes the extras group
// directly — so its only current exercise is TestStripExtras. It stays
// exported so a future reader removes it knowingly rather than by accident.
func StripExtras(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		return strings.TrimSpace(name[:i])
	}
	return strings.TrimSpace(name)
}

// ExcludesLinux reports whether marker is a single, unambiguous PEP 508
// clause proving a dependency is gated to Windows only — the idiom real
// Windows-only packages use (pyreadline3, pywin32). Anything this cannot
// prove — "and"/"or", parens, a python_version comparison, an unrecognized
// key — returns false rather than being guessed at, so a marker the parser
// does not fully understand is never silently excluded from coverage; it
// still surfaces via the pypi.marker attribute for a human or an automated
// reader to judge.
func ExcludesLinux(marker string) bool {
	m := strings.ToLower(strings.Join(strings.Fields(marker), ""))
	switch m {
	case `sys_platform=='win32'`, `sys_platform=="win32"`,
		`os_name=='nt'`, `os_name=="nt"`,
		`platform_system=='windows'`, `platform_system=="windows"`:
		return true
	default:
		return false
	}
}

// GatedByExtra reports whether marker conditions a dependency on an extra
// being requested (e.g. `extra == "async"`). A tool that never claims to
// know which extras were requested cannot confirm such a dependency was
// actually pulled in, so callers reconstructing edges from `requires_dist`
// must skip anything this reports true for rather than assume the extra
// was active.
func GatedByExtra(marker string) bool {
	return strings.Contains(marker, "extra")
}
