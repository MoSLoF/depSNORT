package pypi

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
)

// pyproject.toml support.
//
// A pyproject is a MANIFEST, not a lockfile: it declares dependencies with
// constraints and no resolved versions. So it produces a root whose declared
// deps ride on graph.AttrDeclaredDeps, and transitive expansion presumes a
// version for each (D-44). Before this, a Poetry/PEP 621 project with no
// requirements.txt or lockfile resolved to nothing — "no supported projects
// found" — which the trial-by-fire caught on a real repo.
//
// Two dependency dialects are read, both line-scanned rather than with a TOML
// parser (Decision D-10 forbids a third-party TOML dependency, and only two
// simple table shapes are needed):
//
//   - PEP 621: [project] dependencies = ["fastapi>=0.100", "pyyaml (>=6.0)"]
//   - Poetry:  [tool.poetry.dependencies] with `name = "constraint"` lines
//
// Nothing here executes the project or runs a build backend (D-04): it reads
// the two tables and stops.

// pyprojectDeclaresDeps reports whether a pyproject.toml actually declares
// dependencies in a shape this adapter reads. Detection gates on it so a
// pyproject that only configures a build backend (no deps) is not claimed as a
// resolvable project — it stays install-surface only, as before.
func pyprojectDeclaresDeps(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	deps, _ := parsePyprojectDeps(raw)
	return len(deps) > 0
}

func parsePyproject(path string, raw []byte) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, path)

	deps, poetry := parsePyprojectDeps(raw)
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["pypi.source"] = pyprojectName

	// A pyproject declares direct deps but resolves no tree: every dep is
	// unpinned-by-construction, so all of them are the declared-deps channel and
	// the coverage disclosure both. Names go to AttrUnresolved (coverage), the
	// name+constraint pairs to AttrDeclaredDeps (for expansion).
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
	if len(out) == 0 {
		return nil, errNoPyprojectDeps
	}
	sortDeclared(out)
	sortStrings(names)
	root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(out)
	root.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
	root.Attr[graph.AttrUnresolvedCount] = itoa(len(names))
	// A manifest records no inter-package structure, so the tree below the root
	// is one layer deep by construction until expansion runs — the same
	// flat-resolution fact a bare requirements.txt carries (D-24).
	root.Attr[graph.AttrFlatResolution] = "pypi"
	_ = poetry
	return g, nil
}

// parsePyprojectDeps extracts declared dependencies from both the PEP 621 array
// and the Poetry table. poetry reports whether the Poetry table was the source,
// so a caller can note the dialect.
func parsePyprojectDeps(raw []byte) (deps []graph.DeclaredDep, poetry bool) {
	lines := strings.Split(string(raw), "\n")

	// --- PEP 621: [project] ... dependencies = [ "...", "..." ] ---
	if arr := extractArray(lines, "[project]", "dependencies"); arr != nil {
		for _, item := range arr {
			if d, ok := declFromPEP508(item); ok {
				deps = append(deps, d)
			}
		}
	}

	// --- PEP 621 extras: [project.optional-dependencies] (OPU-12 D-1) ---
	//
	// Each key under the section is a named extra whose value is a PEP 508 array.
	// A default install pulls none of them, but a supply-chain IDS must see the
	// full declared surface: for soup-cli that is 55 of 62 declared packages —
	// the entire heavy stack (torch, transformers, vllm, …) lives here and was
	// invisible before. We emit the UNION of every extra's dependencies (the
	// maximal set any install could pull), deduped by name downstream.
	//
	// Two hazards the extras block introduces:
	//   - Self-reference: a meta-extra like `all = ["soup-cli[train,mlx]"]` or
	//     `dev = ["soup-cli[all]"]` names the project's OWN distribution to pull
	//     in its local extras. Emitting that name would be a dependency-confusion
	//     false positive on the project itself — and it is redundant, because
	//     every extra is already iterated into the union. So a self-reference is
	//     skipped, not emitted.
	//   - Cross-extra pin split: `train` pins `transformers<5.0.0`, `mlx` pins
	//     `>=5.0.0`. These are mutually exclusive PROFILES, not a contradiction.
	//     Because declared deps are deduped by NAME downstream (one constraint per
	//     package reaches expansion), the two never accumulate onto one node, so
	//     the split is not mis-reported as `contested`. Extras are iterated in
	//     sorted order so which representative constraint survives is deterministic.
	projName := purl.NormalizePyPI(pyprojectProjectName(lines))
	extras := extractNamedArrays(lines, "[project.optional-dependencies]")
	for _, extra := range sortedKeys(extras) {
		for _, item := range extras[extra] {
			rawName, _, _ := pep508.SplitSpecifier(item)
			if projName != "" && purl.NormalizePyPI(pep508.StripExtras(rawName)) == projName {
				continue // self-reference to a local extra; its deps are already in the union
			}
			if d, ok := declFromPEP508(item); ok {
				deps = append(deps, d)
			}
		}
	}

	// --- Poetry: [tool.poetry.dependencies] name = "constraint" ---
	for _, kv := range extractTable(lines, "[tool.poetry.dependencies]") {
		name := strings.TrimSpace(kv[0])
		// python itself is not a package (it is the interpreter constraint),
		// mirroring the platform-package filter the Composer walk applies.
		if name == "" || strings.EqualFold(name, "python") {
			continue
		}
		poetry = true
		constraint := parsePoetryConstraint(kv[1])
		deps = append(deps, graph.DeclaredDep{Name: purl.NormalizePyPI(name), Constraint: constraint})
	}
	return deps, poetry
}

// declFromPEP508 turns one PEP 508 requirement string into a declared dep,
// keeping the version specifier and dropping extras/markers. A platform-only or
// URL requirement (no readable name) is skipped.
func declFromPEP508(s string) (graph.DeclaredDep, bool) {
	name, spec, marker := pep508.SplitSpecifier(s)
	name = pep508.StripExtras(name)
	if name == "" {
		return graph.DeclaredDep{}, false
	}
	if marker != "" && pep508.ExcludesLinux(marker) {
		return graph.DeclaredDep{}, false
	}
	return graph.DeclaredDep{Name: purl.NormalizePyPI(name), Constraint: spec}, true
}

// parsePoetryConstraint reduces a Poetry dependency value to a version
// constraint string this tool's PEP 440 evaluator can read. Poetry uses caret
// and tilde (^1.2, ~1.2) plus plain specifiers, and a table form
// `{version = "^1.2", ...}` for extras/markers. Anything else yields "" (no
// constraint = any), which is honest: an unreadable form must not become a
// false pin.
func parsePoetryConstraint(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	if strings.HasPrefix(v, "{") {
		// Inline table: pull out version = "..." if present.
		if i := strings.Index(v, "version"); i >= 0 {
			rest := v[i+len("version"):]
			if j := strings.Index(rest, "="); j >= 0 {
				rest = strings.TrimSpace(rest[j+1:])
				rest = strings.TrimLeft(rest, `"'`)
				if k := strings.IndexAny(rest, `"',}`); k >= 0 {
					return strings.TrimSpace(rest[:k])
				}
			}
		}
		return ""
	}
	if v == "*" {
		return ""
	}
	return v
}

// extractArray returns the string items of `key = [ ... ]` inside the given
// section header, spanning multiple lines. Returns nil if not found.
func extractArray(lines []string, section, key string) []string {
	inSection := section == "" // "" means search from the top
	var collecting bool
	var buf strings.Builder
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if !collecting {
			// Section tracking. A quoted array ELEMENT ("requests[security]") begins
			// with a quote, never '[', so this only matches real section headers.
			if strings.HasPrefix(line, "[") && line != section {
				inSection = (line == section)
				continue
			}
			if line == section {
				inSection = true
				continue
			}
			if !inSection {
				continue
			}
			_, v, ok := cutKey(line, key)
			if !ok {
				continue
			}
			open := strings.Index(v, "[")
			if open < 0 {
				continue
			}
			collecting = true
			buf.WriteString(stripArrayLineComment(v[open+1:]))
		} else {
			// A new section header ends an unterminated array (malformed; a
			// well-formed one closes with its ']' first, caught below).
			if strings.HasPrefix(line, "[") {
				break
			}
			buf.WriteString("\n")
			// Strip any trailing TOML comment BEFORE the line joins the buffer:
			// quotedItems extracts every quoted token, so a quoted word inside an
			// in-array comment ("# a silent \"clean\" without it") would otherwise
			// be minted as a phantom dependency (OPU-11).
			buf.WriteString(stripArrayLineComment(raw))
		}
		// Close the array at the ']' that sits at bracket depth 0 OUTSIDE any
		// quoted string — NOT at the first ']', which for an element like
		// "requests[security]>=2.0" is the extras bracket inside the string. That
		// naive first-']' bound collapsed the whole array to empty, so an
		// extras-bearing pyproject read as "no dependencies" and the project was
		// silently skipped (OPU-10).
		if idx := topLevelCloseBracket(buf.String()); idx >= 0 {
			// Items are quoted strings; extract them by quote boundaries rather than
			// by comma, because a PEP 508 constraint contains commas (">=1,<2") that
			// must not split one requirement into two.
			return quotedItems(buf.String()[:idx])
		}
	}
	if buf.Len() == 0 {
		return nil
	}
	return quotedItems(buf.String())
}

// topLevelCloseBracket returns the index of the ']' that closes an array whose
// opening '[' has already been consumed: the first ']' seen at bracket depth 0
// while not inside a quoted string. A ']' inside quotes (a PEP 508 extras marker
// like "requests[security]") or nested one edit deep does not close the array.
// Returns -1 when the array is not yet closed.
func topLevelCloseBracket(s string) int {
	depth := 0
	var quote byte // 0 = outside a quote, else the opening quote character
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '[':
			depth++
		case ']':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// pyprojectProjectName returns the [project] name field (unquoted), or "" if
// absent. Used to recognize a self-referential extra (myproj[extra]) so the
// project's own distribution name is never emitted as an external dependency.
func pyprojectProjectName(lines []string) string {
	for _, kv := range extractTable(lines, "[project]") {
		if strings.TrimSpace(kv[0]) == "name" {
			return strings.Trim(strings.TrimSpace(kv[1]), `"'`)
		}
	}
	return ""
}

// extractNamedArrays returns every `key = [ ... ]` array declared under section,
// keyed by its key — the shape [project.optional-dependencies] uses (one PEP 508
// array per extra name). It spans multi-line arrays and strips trailing TOML
// comments per line (OPU-11), reusing the same quote-aware bracket matching as
// extractArray so a ']' inside a quoted requirement does not close the array
// early.
func extractNamedArrays(lines []string, section string) map[string][]string {
	out := map[string][]string{}
	inSection := section == ""
	collecting := false
	var curKey string
	var buf strings.Builder
	finish := func() {
		if s := buf.String(); curKey != "" {
			if idx := topLevelCloseBracket(s); idx >= 0 {
				out[curKey] = quotedItems(s[:idx])
			} else {
				out[curKey] = quotedItems(s)
			}
		}
		buf.Reset()
		curKey = ""
		collecting = false
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if !collecting {
			if strings.HasPrefix(line, "[") {
				inSection = (line == section)
				continue
			}
			if !inSection || line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			i := strings.Index(line, "=")
			if i < 0 {
				continue
			}
			open := strings.Index(line[i+1:], "[")
			if open < 0 {
				continue // not an array value
			}
			curKey = strings.TrimSpace(line[:i])
			collecting = true
			buf.WriteString(stripArrayLineComment(line[i+1+open+1:]))
			if idx := topLevelCloseBracket(buf.String()); idx >= 0 {
				finish()
			}
			continue
		}
		// A new section header ends an unterminated array (malformed).
		if strings.HasPrefix(line, "[") {
			finish()
			inSection = (line == section)
			continue
		}
		buf.WriteString("\n")
		buf.WriteString(stripArrayLineComment(raw))
		if idx := topLevelCloseBracket(buf.String()); idx >= 0 {
			finish()
		}
	}
	if collecting {
		finish()
	}
	return out
}

// sortedKeys returns the map keys in sorted order, for deterministic iteration.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extractTable returns key/value pairs under a section header until the next
// section. Each pair is [key, rawValue].
func extractTable(lines []string, section string) [][2]string {
	var out [][2]string
	inSection := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			inSection = (line == section)
			continue
		}
		if !inSection || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			out = append(out, [2]string{strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])})
		}
	}
	return out
}

func cutKey(line, key string) (k, v string, ok bool) {
	i := strings.Index(line, "=")
	if i < 0 {
		return "", "", false
	}
	if strings.TrimSpace(line[:i]) != key {
		return "", "", false
	}
	return key, strings.TrimSpace(line[i+1:]), true
}

var errNoPyprojectDeps = errors.New("pypi: pyproject.toml declares no readable dependencies")

func sortDeclared(d []graph.DeclaredDep) {
	sort.Slice(d, func(i, j int) bool { return d[i].Name < d[j].Name })
}

func sortStrings(s []string) { sort.Strings(s) }

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// stripArrayLineComment removes a trailing TOML line comment from one line of an
// array body: everything from the first '#' that appears OUTSIDE a quoted string.
// A '#' inside quotes is kept, so a URL requirement's egg fragment
// ("pkg @ git+https://h/r.git#egg=pkg") survives intact. This mirrors the
// quote-tracking in topLevelCloseBracket; without it, quotedItems would harvest
// quoted words out of comments as phantom dependencies (OPU-11).
func stripArrayLineComment(line string) string {
	var quote byte // 0 = outside a quote, else the opening quote char
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '#':
			return line[:i]
		}
	}
	return line
}

// quotedItems returns the contents of each single- or double-quoted string in s,
// ignoring commas and whitespace between them. This is the array-of-strings
// subset a pyproject dependencies list uses.
func quotedItems(s string) []string {
	var items []string
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '"' || c == '\'' {
			j := i + 1
			for j < len(s) && s[j] != c {
				j++
			}
			if j >= len(s) {
				break
			}
			item := strings.TrimSpace(s[i+1 : j])
			if item != "" {
				items = append(items, item)
			}
			i = j + 1
			continue
		}
		i++
	}
	return items
}
