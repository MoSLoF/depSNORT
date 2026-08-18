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
	"sort"
	"strconv"
	"strings"
)

// Qualifier is one PURL qualifier: a key=value pair carried after the version.
type Qualifier struct{ Key, Value string }

// PURL is a parsed package URL. Only the fields depSNORT uses are modeled.
type PURL struct {
	Type      string // e.g. "npm", "pypi"
	Namespace string // e.g. "@scope" for npm (stored WITH the leading @)
	Name      string
	Version   string
	// Qualifiers distinguish packages that share a type/name/version but are
	// NOT the same artifact. Rendered sorted by key, so identity does not
	// depend on construction order.
	//
	// Only non-registry origins carry them. A bare PURL therefore keeps its
	// existing meaning — the canonical registry coordinate — and the graph's
	// transitive dedupe is unaffected for the packages that make up almost
	// every tree.
	Qualifiers []Qualifier
}

// Qualifier keys depSNORT emits. Both are custom rather than the spec's
// vcs_url/download_url, deliberately: one rule ("a non-registry package carries
// its class, and its origin when the lockfile records one") is easier to reason
// about than three keys chosen per class, and these strings are internal
// identity, not an interop surface.
const (
	// QualifierSource is the provenance class: git, path, url (D-41).
	QualifierSource = "source"
	// QualifierSourceRef is the origin itself — a git URL with its revision, a
	// file: reference — when the lockfile records one.
	QualifierSourceRef = "source_ref"
)

// WithSource returns p carrying the qualifiers that distinguish a non-registry
// origin, or p unchanged when the origin is a registry (or unrecorded).
//
// This is what makes a crate vendored from a git fork a DIFFERENT NODE from the
// registry crate of the same name and version (finding DS-REV-02). They are
// different code with different contents; before this they shared one PURL, so
// the graph kept whichever the parser reached first and the other silently
// overwrote its provenance — a registry package could report as git-sourced, or
// a git fork could be masked as registry and slip past VC-009.
//
// The registry case is deliberately left bare. Qualifying it would change the
// identity of essentially every package in every tree, breaking dedupe,
// committed baselines, and IOC ledgers to fix a case that does not exist:
// a registry coordinate is already globally unique.
func (p PURL) WithSource(class, ref string) PURL {
	switch class {
	case "", "registry", "unknown":
		return p
	}
	p.Qualifiers = append(p.Qualifiers, Qualifier{Key: QualifierSource, Value: class})
	if ref != "" {
		p.Qualifiers = append(p.Qualifiers, Qualifier{Key: QualifierSourceRef, Value: ref})
	}
	return p
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
	if q := renderQualifiers(p.Qualifiers); q != "" {
		b.WriteByte('?')
		b.WriteString(q)
	}
	return b.String()
}

// renderQualifiers emits "k=v&k2=v2", sorted by key, with empty values and
// malformed keys dropped and duplicate keys collapsed to the last value.
//
// The normalization matters more than the format: identity is the rendered
// string, so two PURLs describing the same package must render identically no
// matter what order their qualifiers were appended in or how a parsed one was
// spelled.
func renderQualifiers(qs []Qualifier) string {
	if len(qs) == 0 {
		return ""
	}
	byKey := make(map[string]string, len(qs))
	for _, q := range qs {
		if q.Value == "" || !validQualifierKey(q.Key) {
			continue
		}
		byKey[q.Key] = q.Value
	}
	if len(byKey) == 0 {
		return ""
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(encodeQualifierValue(byKey[k]))
	}
	return b.String()
}

// validQualifierKey mirrors the spec: lowercase ASCII letters, digits, ".", "-"
// and "_". A key outside that set is structural garbage — it could contain the
// "&" or "=" that separate qualifiers — so it is dropped rather than rendered
// into a string that would parse back differently.
func validQualifierKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// encodeQualifierValue percent-encodes every character that carries structure
// anywhere in a PURL. A git ref legitimately contains "@", "/", "?" and "#"
// (git+ssh://git@host/o/r.git#rev), and an unencoded one of those would let a
// lockfile forge a version, a namespace, or another qualifier — the same
// identity-forging shape D-33 closed for name and version segments.
func encodeQualifierValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%25")
		case '@':
			b.WriteString("%40")
		case '/':
			b.WriteString("%2F")
		case '?':
			b.WriteString("%3F")
		case '#':
			b.WriteString("%23")
		case '&':
			b.WriteString("%26")
		case '=':
			b.WriteString("%3D")
		default:
			if c < 0x21 || c > 0x7e {
				// Control characters, spaces, and non-ASCII bytes cannot appear
				// raw in an identity string.
				//
				// ZERO-PADDED to two hex digits, which decodeSegment requires:
				// an unpadded "%0" for NUL is not a valid escape, so it decoded
				// as a literal and re-encoded as "%250" — the same string
				// rendering two different identities on successive passes.
				// FuzzParse caught it on the input "pkg:A/0?0=\x00".
				b.WriteString(fmt.Sprintf("%%%02X", c))
				continue
			}
			b.WriteByte(c)
		}
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
	if !strings.ContainsAny(s, "@/%?#") {
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
		case '?':
			// "?" opens the qualifier section and "#" the subpath. Both became
			// structural when qualifiers were added, so both must be encoded
			// here for the same reason "@" and "/" always were: a package named
			// `a?source=git` would otherwise render a PURL that parses back
			// with a FORGED qualifier, letting a hostile lockfile mint the
			// identity of a differently-sourced package. Same shape as the
			// name/version forging D-33 closed; found immediately by FuzzParse
			// when the qualifier parsing landed without it.
			b.WriteString("%3F")
		case '#':
			b.WriteString("%23")
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

	// Subpath and qualifiers are stripped BEFORE the version split, and in that
	// order, because both can legitimately contain "@": a git ref like
	// "git+ssh://git@host/o/r.git#rev" lives in a qualifier value. Splitting on
	// the last "@" first would tear a qualifier in half and put the fragment in
	// the version — which is exactly what this parser did before qualifiers
	// existed, silently, for any PURL carrying one.
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		// depSNORT models no subpath. Dropping it keeps the round trip stable
		// (a re-parse of the rendered form finds nothing to drop).
		rest = rest[:i]
	}
	var quals []Qualifier
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		quals = parseQualifiers(rest[i+1:])
		rest = rest[:i]
	}

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
	p := PURL{Type: parts[0], Version: version, Qualifiers: quals}
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

// parseQualifiers reads "k=v&k2=v2". Malformed pairs are DROPPED rather than
// rejected: a qualifier is decoration on an identity, and refusing to parse a
// PURL because a trailing "&" was stray would turn a cosmetic defect into a
// resolution failure. What matters is that whatever survives re-renders
// identically, which renderQualifiers guarantees by normalizing.
func parseQualifiers(s string) []Qualifier {
	if s == "" {
		return nil
	}
	var out []Qualifier
	for _, pair := range strings.Split(s, "&") {
		i := strings.IndexByte(pair, '=')
		if i <= 0 {
			continue
		}
		key := strings.ToLower(pair[:i])
		val := decodeSegment(pair[i+1:])
		if val == "" || !validQualifierKey(key) {
			continue
		}
		out = append(out, Qualifier{Key: key, Value: val})
	}
	return out
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
