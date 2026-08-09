// Package purl implements the minimal subset of the package-url (PURL) spec
// that dependaSNORT needs to canonically name a package@version node.
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
	"strings"
)

// PURL is a parsed package URL. Only the fields dependaSNORT uses are modeled.
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
	b.WriteString(p.Name)
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(p.Version)
	}
	return b.String()
}

// encodeNamespace percent-encodes the leading "@" (the only reserved char that
// commonly appears in the namespaces we handle today).
func encodeNamespace(ns string) string {
	if strings.HasPrefix(ns, "@") {
		return "%40" + ns[1:]
	}
	return ns
}

// Parse parses a canonical PURL string. It is intentionally lenient about the
// subset of the spec dependaSNORT emits.
func Parse(s string) (PURL, error) {
	if !strings.HasPrefix(s, "pkg:") {
		return PURL{}, fmt.Errorf("purl: missing 'pkg:' scheme in %q", s)
	}
	rest := strings.TrimPrefix(s, "pkg:")

	var version string
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		version = rest[i+1:]
		rest = rest[:i]
	}

	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return PURL{}, fmt.Errorf("purl: expected type/name in %q", s)
	}
	p := PURL{Type: parts[0], Version: version}
	switch len(parts) {
	case 2:
		p.Name = parts[1]
	default:
		p.Namespace = decodeNamespace(strings.Join(parts[1:len(parts)-1], "/"))
		p.Name = parts[len(parts)-1]
	}
	if p.Type == "" || p.Name == "" {
		return PURL{}, fmt.Errorf("purl: empty type or name in %q", s)
	}
	return p, nil
}

func decodeNamespace(ns string) string {
	if strings.HasPrefix(ns, "%40") {
		return "@" + ns[3:]
	}
	return ns
}
