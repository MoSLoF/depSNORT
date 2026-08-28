package clojure

import (
	"fmt"
	"regexp"
	"strings"

	"ihbv.io/depsnort/internal/graph"
)

// dep is one declared dependency as the manifest states it.
type dep struct {
	group    string // Maven groupId
	artifact string // Maven artifactId
	version  string // exact literal pin; "" when the manifest names no usable pin
	// constraint records what the manifest DID say when version is "" — a
	// range string, a symbol, a truncated form — so the declared-deps attr can
	// carry the fact without depSNORT pretending to have resolved it.
	constraint string
	source     string // graph.SourceRegistry / SourceGit / SourcePath
	ref        string // git URL or local path, for AttrSourceRef
}

func (d dep) coordinate() string { return d.group + ":" + d.artifact }

// mavenSymRe is the shape of a Maven-coordinate symbol as Leiningen and
// tools.deps write it: `artifact` or `group/artifact`, each side drawn from
// the characters Maven ids actually use. Anything else (macro output, a
// reader conditional, line noise) is NOT read as a name — the entry is
// disclosed as unparsed instead of a mangled token entering the graph.
var mavenSymRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$`)

// splitCoord maps a Clojure dependency symbol to Maven group:artifact.
// `group/artifact` is explicit; a bare `artifact` means group == artifact —
// Leiningen's own convention ([postgresql "42.7.4"] is
// postgresql:postgresql).
func splitCoord(sym string) (group, artifact string, ok bool) {
	if !mavenSymRe.MatchString(sym) {
		return "", "", false
	}
	if i := strings.IndexByte(sym, '/'); i > 0 {
		return sym[:i], sym[i+1:], true
	}
	return sym, sym, true
}

// literalPin reports whether a version string is an exact Maven version this
// tool may claim as observed. Ranges ("[1.0,2.0)"), the RELEASE/LATEST
// meta-versions, and anything with whitespace are declarations, not pins.
func literalPin(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t\n[](),") {
		return false
	}
	switch v {
	case "RELEASE", "LATEST":
		return false
	}
	return true
}

// skipDiscard advances past a `#_` reader-discard and the single form it
// discards, so a commented-out dependency is neither scanned nor disclosed.
func skipDiscard(s string, i int) int {
	i += 2 // past #_
	i = skipWS(s, i)
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '[', '{', '(':
		return scanBalanced(s, i)
	case '"':
		return scanCljString(s, i)
	default:
		_, i = readSymbol(s, i)
		return i
	}
}

// parseProjectClj reads a Leiningen project.clj: every `:dependencies` vector
// (profiles included — a dev-profile dependency is fetched from the same
// registries and is the same supply-chain surface), each entry
// `[group/artifact "version" & opts]`. It also returns the defproject
// name/version for the root when stated. `:plugins` and `:managed-dependencies`
// are deliberately not read yet (disclosed in the DECISIONS entry, not
// silently dropped: plugins are a Leiningen-process surface, managed deps a
// version-authority question, each its own increment).
func parseProjectClj(src string) (deps []dep, unparsed int, rootName, rootVersion string) {
	s := stripCljComments(src)

	if loc := defprojectRe.FindStringSubmatchIndex(s); loc != nil {
		i := skipWS(s, loc[1])
		sym, j := readSymbol(s, i)
		if mavenSymRe.MatchString(sym) {
			rootName = sym
			j = skipWS(s, j)
			if j < len(s) && s[j] == '"' {
				if v, _ := readString(s, j); literalPin(v) {
					rootVersion = v
				}
			}
		}
	}

	for _, loc := range dependenciesKeyRe.FindAllStringIndex(s, -1) {
		i := skipWS(s, loc[1])
		if i >= len(s) || s[i] != '[' {
			continue
		}
		end := scanBalanced(s, i)
		body := s[i+1 : max(i+1, end-1)]
		d, u := parseDepVector(body)
		deps = append(deps, d...)
		unparsed += u
	}
	return deps, unparsed, rootName, rootVersion
}

var (
	defprojectRe = regexp.MustCompile(`\(\s*defproject\s`)
	// The :dependencies keyword as a key position: preceded by start,
	// whitespace, or an opening bracket, so :managed-dependencies and
	// :plugin-dependencies never match.
	dependenciesKeyRe = regexp.MustCompile(`(?:^|[\s\[{(,]):dependencies\b`)
	depsEdnKeyRe      = regexp.MustCompile(`(?:^|[\s\[{(,]):(deps|extra-deps|replace-deps)\b`)
)

// parseDepVector reads the inside of one :dependencies vector: a sequence of
// `[sym "version" ...]` entries.
func parseDepVector(body string) (deps []dep, unparsed int) {
	i := 0
	for i < len(body) {
		i = skipWS(body, i)
		if i >= len(body) {
			break
		}
		if strings.HasPrefix(body[i:], "#_") {
			i = skipDiscard(body, i)
			continue
		}
		if body[i] != '[' {
			// Not an entry vector (stray metadata, a reader conditional):
			// step over one form and count it — a shape this reader does not
			// understand degrades coverage, it does not vanish.
			i = stepForm(body, i)
			unparsed++
			continue
		}
		end := scanBalanced(body, i)
		entry := body[i+1 : max(i+1, end-1)]
		i = end
		d, ok := parseDepEntry(entry)
		if !ok {
			unparsed++
			continue
		}
		deps = append(deps, d)
	}
	return deps, unparsed
}

// parseDepEntry reads one `[sym "version" & opts]` entry.
func parseDepEntry(entry string) (dep, bool) {
	i := skipWS(entry, 0)
	sym, i := readSymbol(entry, i)
	group, artifact, ok := splitCoord(sym)
	if !ok {
		return dep{}, false
	}
	d := dep{group: group, artifact: artifact, source: graph.SourceRegistry}
	i = skipWS(entry, i)
	if i < len(entry) && entry[i] == '"' {
		v, _ := readString(entry, i)
		if literalPin(v) {
			d.version = v
		} else {
			d.constraint = v
		}
		return d, true
	}
	// No string version: a symbol/expression version ([foo my-version]) is a
	// declaration whose pin lives outside this reader's static reach.
	if i < len(entry) {
		tok, _ := readSymbol(entry, i)
		d.constraint = tok
	}
	return d, true
}

// stepForm advances past one form of any shape.
func stepForm(s string, i int) int {
	switch s[i] {
	case '[', '{', '(':
		return scanBalanced(s, i)
	case '"':
		return scanCljString(s, i)
	default:
		_, j := readSymbol(s, i)
		if j == i {
			return i + 1 // a stray closer or unknown byte: never stall
		}
		return j
	}
}

// parseDepsEdn reads a tools.deps deps.edn: the `:deps` map plus every
// `:extra-deps` and `:replace-deps` map under :aliases (alias deps are fetched
// from the same registries — same surface, same reasoning as lein profiles).
// Each entry is `sym {:mvn/version "v"}` (registry), `sym {:git/url ...}`
// (git), or `sym {:local/root ...}` (path).
func parseDepsEdn(src string) (deps []dep, unparsed int) {
	s := stripCljComments(src)
	for _, loc := range depsEdnKeyRe.FindAllStringSubmatchIndex(s, -1) {
		i := skipWS(s, loc[1])
		if i >= len(s) || s[i] != '{' {
			continue
		}
		end := scanBalanced(s, i)
		body := s[i+1 : max(i+1, end-1)]
		d, u := parseDepsEdnMap(body)
		deps = append(deps, d...)
		unparsed += u
	}
	return deps, unparsed
}

func parseDepsEdnMap(body string) (deps []dep, unparsed int) {
	i := 0
	for i < len(body) {
		i = skipWS(body, i)
		if i >= len(body) {
			break
		}
		if strings.HasPrefix(body[i:], "#_") {
			i = skipDiscard(body, i)
			continue
		}
		sym, j := readSymbol(body, i)
		if j == i { // not a symbol (stray bracket or string): step and count
			i = stepForm(body, i)
			unparsed++
			continue
		}
		i = skipWS(body, j)
		group, artifact, symOK := splitCoord(sym)
		if i >= len(body) || body[i] != '{' {
			// A key with no coordinate map — step over whatever value form is
			// there and count the entry as unparsed.
			if i < len(body) {
				i = stepForm(body, i)
			}
			unparsed++
			continue
		}
		end := scanBalanced(body, i)
		coord := body[i+1 : max(i+1, end-1)]
		i = end
		if !symOK {
			unparsed++
			continue
		}
		d := dep{group: group, artifact: artifact}
		fillCoordMap(&d, coord)
		deps = append(deps, d)
	}
	return deps, unparsed
}

// fillCoordMap reads a deps.edn coordinate map body into d.
func fillCoordMap(d *dep, coord string) {
	d.source = graph.SourceRegistry
	if v := ednStringValue(coord, ":mvn/version"); v != "" {
		if literalPin(v) {
			d.version = v
		} else {
			d.constraint = v
		}
		return
	}
	if u := ednStringValue(coord, ":git/url"); u != "" {
		d.source, d.ref = graph.SourceGit, u
		return
	}
	if strings.Contains(coord, ":git/sha") || strings.Contains(coord, ":git/tag") {
		d.source = graph.SourceGit
		return
	}
	if p := ednStringValue(coord, ":local/root"); p != "" {
		d.source, d.ref = graph.SourcePath, p
		return
	}
	// A coordinate shape this reader does not know: declared, unresolved.
	d.constraint = strings.TrimSpace(truncate(coord, 40))
}

// ednStringValue finds `key "value"` inside a coordinate map body.
func ednStringValue(body, key string) string {
	idx := strings.Index(body, key)
	if idx < 0 {
		return ""
	}
	i := skipWS(body, idx+len(key))
	if i >= len(body) || body[i] != '"' {
		return ""
	}
	v, _ := readString(body, i)
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%s…", s[:n])
}
