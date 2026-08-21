package pypi

// Pipfile support.
//
// A Pipfile is pipenv's MANIFEST, not a lockfile: it declares dependencies with
// constraints (often just "*") and resolves no versions or transitive tree —
// that is Pipfile.lock's job, which the pypi adapter already parses. So a
// Pipfile is handled exactly like pyproject.toml: it produces a root whose
// declared deps ride on graph.AttrDeclaredDeps (so expansion can presume a
// version, D-44), with the same flat-resolution disclosure a bare
// requirements.txt carries (D-24).
//
// It is reached ONLY when there is no Pipfile.lock in the directory (the lock is
// richer and is preferred by inputPath), and only when it actually declares
// dependencies — a Pipfile that declares none is left to the coverage-gap
// disclosure, unchanged. Line-scanned, not TOML-parsed (Decision D-10); only the
// [packages] and [dev-packages] tables are read, and nothing is executed (D-04).

import (
	"errors"
	"os"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

const pipfileName = "Pipfile"

var errNoPipfileDeps = errors.New("pypi: Pipfile declares no readable dependencies")

// pipfileDeclaresDeps reports whether a Pipfile declares dependencies in a shape
// this adapter reads. Detection gates on it so an empty Pipfile is not claimed
// as a resolvable project (it stays a disclosed coverage gap, as before).
func pipfileDeclaresDeps(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return len(parsePipfileDeps(raw)) > 0
}

func parsePipfile(path string, raw []byte) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, path)
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["pypi.source"] = pipfileName

	var names []string
	seen := map[string]bool{}
	out := make([]graph.DeclaredDep, 0)
	for _, d := range parsePipfileDeps(raw) {
		if d.Name == "" || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		out = append(out, d)
		names = append(names, d.Name)
	}
	if len(out) == 0 {
		return nil, errNoPipfileDeps
	}
	sortDeclared(out)
	sortStrings(names)
	root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(out)
	root.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
	root.Attr[graph.AttrUnresolvedCount] = itoa(len(names))
	// A manifest records no inter-package structure, so the tree is one layer
	// deep by construction until expansion runs (D-24).
	root.Attr[graph.AttrFlatResolution] = "pypi"
	return g, nil
}

// parsePipfileDeps line-scans the [packages] and [dev-packages] tables. The TOML
// key is the package name; the value is a specifier string ("*", ">=2.0") or an
// inline table ({version = "...", extras = [...]}) whose version is taken (else
// "*" when a table pins no version, e.g. a git/path dependency).
func parsePipfileDeps(raw []byte) []graph.DeclaredDep {
	var out []graph.DeclaredDep
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") {
			if t == "[packages]" || t == "[dev-packages]" {
				section = t
			} else {
				section = "" // [[source]], [requires], [scripts], [pipenv], ...
			}
			continue
		}
		if section != "[packages]" && section != "[dev-packages]" {
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(t[:eq]), `"'`)
		if name == "" {
			continue
		}
		constraint := pipfileConstraint(strings.TrimSpace(t[eq+1:]))
		out = append(out, graph.DeclaredDep{Name: purl.NormalizePyPI(name), Constraint: constraint})
	}
	return out
}

// pipfileConstraint extracts a version constraint from a Pipfile value: a bare
// quoted string, or an inline table from which `version` is pulled ("*" when a
// table pins no version).
func pipfileConstraint(val string) string {
	if strings.HasPrefix(val, "{") {
		if i := strings.Index(val, "version"); i >= 0 {
			if e := strings.IndexByte(val[i:], '='); e >= 0 {
				if v := firstQuoted(val[i+e+1:]); v != "" {
					return v
				}
			}
		}
		return "*"
	}
	return strings.Trim(val, `"'`)
}
