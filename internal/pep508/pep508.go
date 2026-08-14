// Package pep508 implements the minimal subset of PEP 508 (Python dependency
// specifiers) that depSNORT needs: splitting a requirement string into its
// name/version/marker parts, and judging whether a marker proves a
// dependency is platform-gated. It has no dependency on any ecosystem
// adapter so both internal/datasource/registry (which fetches PyPI
// `requires_dist` metadata) and internal/installsurface (which reads
// `build-system.requires` out of pyproject.toml) can import it without
// creating an import cycle through internal/ecosystem/pypi.
package pep508

import "strings"

// Split splits "name[extra]==1.2.3 ; marker" into its name, version, and
// PEP 508 environment marker (if any). pinned is false for any specifier
// that is not an exact `==` pin. marker is returned verbatim (untrimmed of
// internal spacing beyond the outer TrimSpace) so it can be surfaced to the
// caller rather than silently discarded.
func Split(s string) (name, version string, pinned bool, marker string) {
	// Environment markers: "pkg==1.0 ; python_version < '3.9'"
	if i := strings.IndexByte(s, ';'); i >= 0 {
		marker = strings.TrimSpace(s[i+1:])
		s = strings.TrimSpace(s[:i])
	}
	s = unwrapLegacyParenSpec(s)
	if i := strings.Index(s, "=="); i >= 0 {
		name = strings.TrimSpace(s[:i])
		version = strings.TrimSpace(s[i+2:])
		version = strings.TrimSuffix(version, ".*")
		name = StripExtras(name)
		if name != "" && version != "" {
			return name, version, true, marker
		}
		return name, "", false, marker
	}
	// Any other specifier is unpinned for our purposes.
	for _, op := range []string{">=", "<=", "~=", "!=", ">", "<", "@"} {
		if i := strings.Index(s, op); i >= 0 {
			return StripExtras(strings.TrimSpace(s[:i])), "", false, marker
		}
	}
	return StripExtras(strings.TrimSpace(s)), "", false, marker
}

// unwrapLegacyParenSpec normalizes PyPI JSON API's legacy PEP 345-style
// requires_dist form, "name (>=1.2.3)", to the plain PEP 508 form the rest of
// Split expects, "name >=1.2.3". requirements.txt-style callers never
// produce this shape, so it is a no-op for them (StripExtras'd names never
// contain unmatched parens either). Left untouched if s doesn't look like
// "name (...)" — including a bare "(local version)" with no name before it,
// which would otherwise truncate name to empty.
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
