// Package purl implements the minimal subset of the package-url (PURL) spec
// that depSNORT needs to canonically name a package@version node.
//
// Canonical form: pkg:<type>/<namespace>/<name>@<version>
// The namespace segment is omitted when empty. For npm scoped packages the
// leading "@" of the scope is percent-encoded as %40 per the PURL spec, so
// "@scope/pkg" at 1.2.3 becomes: pkg:npm/%40scope/pkg@1.2.3
//
// Node identity across the whole tool is the PURL string. Two dependency
// entries that resolve to the same type/namespace/name/version are the same
// node — this is what lets the graph dedupe the transitive explosion.
package purl

import (
	"fmt"
	"strconv"
	"strings"
)

// PURL is a parsed package URL. Only the fields depSNORT uses are modeled.
type PURL struct {
	Type      string // e.g. "npm", "pypi"
	Namespace string // e.g. "@scope" for npm (stored WITH the leading @)
	Name      string
	Version   string
}

// NewNpm builds a PURL from an npm package name (which may be scoped like
// "@scope/pkg") and a resolved version.
func NewNpm(name, version string) PURL {
	ns, n := splitNpmScope(name)
	return PURL{Type: "npm", Namespace: ns, Name: n, Version: version}
}

// NewPyPI builds a PURL from a PyPI project name and version. The name is
// normalized per PEP 503 (lowercase; runs of -, _ and . collapse to a single -),
// so "Flask_SQLAlchemy" and "flask-sqlalchemy" resolve to the same node. Without
// this the graph would carry the same package under several identities and the
// transitive dedupe would silently fail.
func NewPyPI(name, version string) PURL {
	return PURL{Type: "pypi", Name: NormalizePyPI(name), Version: version}
}

// NewGem builds a PURL for a RubyGem. Gem names are case-sensitive but
// conventionally lowercase; no normalization beyond trimming.
func NewGem(name, version string) PURL {
	return PURL{Type: "gem", Name: strings.TrimSpace(name), Version: version}
}

// NewCargo builds a PURL for a Cargo (Rust) crate. Crate names are
// case-sensitive and use hyphens as the canonical separator.
func NewCargo(name, version string) PURL {
	return PURL{Type: "cargo", Name: strings.TrimSpace(name), Version: version}
}

// NewComposer builds a PURL for a Composer (PHP) package. Composer packages
// are always vendor/package (two segments). The vendor is the namespace.
func NewComposer(name, version string) PURL {
	name = strings.TrimSpace(name)
	if i := strings.IndexByte(name, '/'); i > 0 {
		return PURL{Type: "composer", Namespace: name[:i], Name: name[i+1:], Version: version}
	}
	return PURL{Type: "composer", Name: name, Version: version}
}

// NewNuGet builds a PURL for a NuGet (.NET) package. NuGet names are
// case-insensitive; we lowercase for deduplication.
func NewNuGet(name, version string) PURL {
	return PURL{Type: "nuget", Name: strings.ToLower(strings.TrimSpace(name)), Version: version}
}

// NormalizePyPI applies PEP 503 name normalization.
func NormalizePyPI(name string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

// splitNpmScope separates "@scope/pkg" into ("@scope", "pkg"). Unscoped names
// return ("", name).
func splitNpmScope(name string) (namespace, bare string) {
	if strings.HasPrefix(name, "@") {
		if i := strings.IndexByte(name, '/'); i > 0 {
			return name[:i], name[i+1:]
		}
	}
	return "", name
}

// String returns the canonical PURL string.
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		b.WriteString(encodeNamespace(p.Namespace))
		b.WriteByte('/')
	}
	b.WriteString(encodeSegment(p.Name))
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(encodeSegment(p.Version))
	}
	return b.String()
}

// Structural characters must be percent-encoded inside a component, or a value
// can forge PURL structure (Decision D-33, found by FuzzParse).
//
// Node identity across the whole tool IS the PURL string. A package name
// containing "@" would otherwise render an extra version separator, so a hostile
// lockfile could declare a package that collides with — or slips past — another
// package's identity: `name="lodash@4.17.21", version=""` renders exactly like
// the real lodash@4.17.21, and an IOC ledger entry keyed on a PURL could be
// evaded the same way. Encoding "@" (separator), "/" (segment separator), and
// "%" (so the encoding is reversible) makes every component unambiguous.
//
// Legitimate package names contain none of these — npm scopes are carried in
// Namespace, and Composer vendors are split off — so canonical output for real
// packages is unchanged.
func encodeSegment(s string) string {
	if !strings.ContainsAny(s, "@/%") {
		return s // fast path: the overwhelmingly common case
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '@':
			b.WriteString("%40")
		case '/':
			b.WriteString("%2F")
		case '%':
			b.WriteString("%25")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// decodeSegment reverses encodeSegment. It is a single left-to-right pass so
// that a literal percent (encoded "%25") cannot be re-decoded into a structural
// character on a second pass — "%2540" must decode to "%40", never to "@".
func decodeSegment(s string) string {
	if !strings.ContainsAny(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+3 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// encodeNamespace percent-encodes structural characters in a namespace. "/" is
// deliberately NOT encoded: a namespace may legitimately span several segments
// and they are joined with "/".
func encodeNamespace(ns string) string {
	var b strings.Builder
	for i := 0; i < len(ns); i++ {
		switch ns[i] {
		case '@':
			b.WriteString("%40")
		case '%':
			b.WriteString("%25")
		default:
			b.WriteByte(ns[i])
		}
	}
	return b.String()
}

// Parse parses a canonical PURL string. It is intentionally lenient about the
// subset of the spec depSNORT emits.
func Parse(s string) (PURL, error) {
	if !strings.HasPrefix(s, "pkg:") {
		return PURL{}, fmt.Errorf("purl: missing 'pkg:' scheme in %q", s)
	}
	rest := strings.TrimPrefix(s, "pkg:")

	var version string
	// A trailing "@" with nothing after it is NOT a version separator. Consuming
	// it would drop a character that String() never re-emits, so Parse->String
	// would lose one "@" per pass and the same package could normalize to two
	// different identities (Decision D-33, found by FuzzParse).
	if i := strings.LastIndexByte(rest, '@'); i >= 0 && i+1 < len(rest) {
		version = decodeSegment(rest[i+1:])
		rest = rest[:i]
	}

	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return PURL{}, fmt.Errorf("purl: expected type/name in %q", s)
	}
	p := PURL{Type: parts[0], Version: version}
	switch len(parts) {
	case 2:
		p.Name = decodeSegment(parts[1])
	default:
		p.Namespace = decodeNamespace(strings.Join(parts[1:len(parts)-1], "/"))
		p.Name = decodeSegment(parts[len(parts)-1])
	}
	if p.Type == "" || p.Name == "" {
		return PURL{}, fmt.Errorf("purl: empty type or name in %q", s)
	}
	// The type is structural: it is read before both the "/" and "@" splits, so a
	// type carrying either character makes the rest of the parse meaningless and
	// the result unrenderable (Decision D-33, found by FuzzParse). The spec
	// restricts it to an ASCII letter followed by letters, digits, ".", "+", "-";
	// depSNORT only ever emits npm/pypi/gem/cargo/composer/nuget.
	if !validType(p.Type) {
		return PURL{}, fmt.Errorf("purl: invalid type %q in %q", p.Type, s)
	}
	return p, nil
}

// validType reports whether t is a syntactically valid PURL type.
func validType(t string) bool {
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '+' || c == '-'):
		default:
			return false
		}
	}
	return t != ""
}

func decodeNamespace(ns string) string { return decodeSegment(ns) }
