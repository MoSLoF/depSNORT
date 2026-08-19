package pypi

import (
	"os"
	"regexp"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
)

// setup.py support — STATIC extraction only.
//
// setup.py is arbitrary Python, and D-04 forbids executing it, so this reads
// two shapes without running anything and declines on everything else:
//
//	install_requires=["cryptography>=3.4.7", "pyserial>=3.5"]   # inline literal
//	requirements = ["cryptography>=3.4.7", ...]                 # a list variable
//	install_requires=requirements                              # passed by name
//
// A setup.py that builds its dependency list dynamically (reads a file, calls
// parse_requirements, comprehends over something) yields no deps here, and the
// file is then NOT claimed as a resolvable project — better to miss it than to
// assert a dependency set the code does not actually declare. The trial-by-fire
// found this on a real project (Reticulum) whose deps are static literals
// assigned to a variable, the common case this handles.

var installRequiresRe = regexp.MustCompile(`install_requires\s*=\s*`)

// setuppyDeclaresDeps reports whether a setup.py statically declares
// dependencies this extractor can read.
func setuppyDeclaresDeps(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return len(parseSetupPyDeps(raw)) > 0
}

func parseSetupPy(path string, raw []byte) (*graph.Graph, error) {
	deps := parseSetupPyDeps(raw)
	if len(deps) == 0 {
		return nil, errNoPyprojectDeps
	}
	g := graph.New()
	root := rootNode(g, path)
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["pypi.source"] = "setup.py"

	var names []string
	seen := map[string]bool{}
	out := make([]graph.DeclaredDep, 0, len(deps))
	for _, d := range deps {
		if d.Name == "" || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		out = append(out, d)
		names = append(names, d.Name)
	}
	sortDeclared(out)
	sortStrings(names)
	root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(out)
	root.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
	root.Attr[graph.AttrUnresolvedCount] = itoa(len(names))
	root.Attr[graph.AttrFlatResolution] = "pypi"
	return g, nil
}

// parseSetupPyDeps extracts declared dependencies from the two static shapes.
func parseSetupPyDeps(raw []byte) []graph.DeclaredDep {
	src := string(raw)

	// Locate the install_requires value.
	loc := installRequiresRe.FindStringIndex(src)
	if loc == nil {
		return nil
	}
	after := strings.TrimLeft(src[loc[1]:], " \t")

	var items []string
	if strings.HasPrefix(after, "[") {
		// Inline literal list, possibly spanning lines up to the matching "]".
		if end := strings.Index(after, "]"); end >= 0 {
			items = quotedItems(after[1:end])
		}
	} else {
		// install_requires=<identifier>: find that variable's list literal(s).
		ident := leadingIdentifier(after)
		if ident == "" {
			return nil
		}
		items = listLiteralsFor(src, ident)
	}

	var deps []graph.DeclaredDep
	for _, it := range items {
		name, spec, marker := pep508.SplitSpecifier(it)
		name = pep508.StripExtras(name)
		if name == "" {
			continue
		}
		if marker != "" && pep508.ExcludesLinux(marker) {
			continue
		}
		deps = append(deps, graph.DeclaredDep{Name: purl.NormalizePyPI(name), Constraint: spec})
	}
	return deps
}

// leadingIdentifier returns the Python identifier at the start of s, or "".
func leadingIdentifier(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	return s[:i]
}

// listLiteralsFor finds every `<ident> = [ ... ]` assignment and returns the
// union of the quoted items across them. A setup.py commonly assigns the list
// twice under a conditional (a pure-python branch with [] and a full branch with
// the real deps); taking the union keeps whichever branch has the dependencies.
func listLiteralsFor(src, ident string) []string {
	var out []string
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(ident) + `\s*=\s*\[`)
	for _, loc := range re.FindAllStringIndex(src, -1) {
		rest := src[loc[1]:] // just after the "["
		if end := strings.Index(rest, "]"); end >= 0 {
			out = append(out, quotedItems(rest[:end])...)
		}
	}
	return out
}
