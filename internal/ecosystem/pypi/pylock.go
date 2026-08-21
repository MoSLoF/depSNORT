package pypi

// pylock.toml support — Tier 4 of the PyPI TOML-lockfile family (PEP 751).
//
// pylock.toml is the standardized, tool-agnostic lock file approved in PEP 751
// and maintained as a PyPA spec. Like uv.lock / poetry.lock / pdm.lock it is a
// fully-resolved TOML lockfile, so the same constraints and the same remedy
// apply: Decision D-10 forbids third-party dependencies and Go ships no TOML
// parser, so this is a line scanner over the constrained subset a lockfile uses
// ([[packages]] table arrays, `key = "value"` scalars, inline `{ name = "x" }`
// tables, `key = [ ... ]` arrays, and the source sub-tables) — not general TOML.
//
// pylock.toml differs from the sibling readers in three ways that shape it:
//
//  1. No root project. Like poetry.lock / pdm.lock, there is no project entry;
//     the root is synthesized and attached to the in-degree-zero packages (the
//     effective direct set), disclosed via pypi.direct_attribution.
//
//  2. Edges are OPTIONAL. `[[packages.dependencies]]` is defined as purely
//     informational (installers MUST NOT use it), and most tools omit it today
//     (uv, pipenv). When it is absent for EVERY package the graph has no edges
//     to reconstruct, so this reader falls back to flat resolution and DISCLOSES
//     it (AttrFlatResolution, Decision D-24) exactly like Pipfile.lock — depths
//     are then presumed, not observed. When edges ARE present the real tree is
//     built and no flat-resolution penalty applies.
//
//  3. Many source shapes. A package's provenance may be an index (registry), a
//     vcs / directory / archive direct reference, or sdist/wheels file URLs.
//     These are classified to a single (kind, ref) with a fixed precedence.
//
// Versions read here are TruthObserved (the graph default): the locker resolved
// and pinned them.

import (
	"bufio"
	"fmt"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

const pylockName = "pylock.toml"

// pylockVersionSupported is the lock-version this reader targets. PEP 751 fixes
// the only valid value at "1.0"; a future version is parsed best-effort and the
// mismatch disclosed on the synthesized root (disclose, don't invent).
const pylockVersionSupported = "1.0"

type pylockPackage struct {
	name    string
	version string
	marker  string
	index   string // packages.index — registry base URL
	deps    []uvDep

	// Source signals, resolved to one (kind, ref) by classify().
	vcsRef     string // vcs.url | vcs.path | vcs.commit-id
	dirPath    string // directory.path
	archiveRef string // archive.url | archive.path
	sdistRef   string // sdist.url | sdist.path
	wheelRef   string // first wheels[].url | wheels[].path
}

// classify collapses the mutually-exclusive PEP 751 source shapes to a single
// provenance. Precedence follows specificity: a direct reference (vcs, local
// directory, archive) over the index the file was found in, over a bare
// sdist/wheel URL with no index.
func (p *pylockPackage) classify() (kind, ref string) {
	switch {
	case p.vcsRef != "":
		return graph.SourceGit, p.vcsRef
	case p.dirPath != "":
		return graph.SourcePath, p.dirPath
	case p.archiveRef != "":
		return graph.SourceURL, p.archiveRef
	case p.index != "":
		return graph.SourceRegistry, p.index
	case p.sdistRef != "":
		return graph.SourceURL, p.sdistRef
	case p.wheelRef != "":
		return graph.SourceURL, p.wheelRef
	default:
		return "", ""
	}
}

func parsePylock(path string, raw []byte) (*graph.Graph, error) {
	lockVersion, pkgs := scanPylock(raw)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("pypi: %s contained no [[packages]] entries", pylockName)
	}

	g := graph.New()
	idOf := func(p *pylockPackage) string { return purl.NewPyPI(p.name, p.version).String() }

	// Nodes: one per locked package with a stable identity. The spec forbids a
	// version on a source-tree entry; such an entry has no pinned identity to
	// scan, so it is skipped for node creation and disclosed on its dependers.
	for i := range pkgs {
		p := &pkgs[i]
		if p.name == "" || p.version == "" {
			continue
		}
		n := g.AddNode(&graph.Node{
			ID:        idOf(p),
			Ecosystem: "pypi",
			Name:      purl.NormalizePyPI(p.name),
			Version:   p.version,
			Attr:      map[string]string{"pypi.source": pylockName},
		})
		if kind, ref := p.classify(); kind != "" {
			n.SetSource(kind, ref)
		}
		if p.marker != "" {
			n.Attr["pypi.marker"] = truncatePylock(p.marker, 200)
		}
	}

	byName := map[string]string{} // normalized name -> node ID (last wins; multi-marker dupes disclosed)
	for i := range pkgs {
		p := &pkgs[i]
		if p.name == "" || p.version == "" {
			continue
		}
		byName[purl.NormalizePyPI(p.name)] = idOf(p)
	}

	// Inter-package edges from the informational `dependencies` tables, when the
	// locker recorded them. edgeCount tells us whether the graph is edged at all.
	indeg := map[string]int{}
	edgeCount := 0
	for i := range pkgs {
		p := &pkgs[i]
		if p.name == "" || p.version == "" {
			continue
		}
		fromID := idOf(p)
		var missing []string
		for _, d := range p.deps {
			toID, ok := byName[purl.NormalizePyPI(d.name)]
			if !ok {
				missing = append(missing, d.name)
				continue
			}
			g.AddEdge(fromID, toID, graph.EdgeDependsOn)
			indeg[toID]++
			edgeCount++
		}
		if len(missing) > 0 {
			markUnresolved(g.Get(fromID), missing)
		}
	}

	// Synthesize the root and attach the in-degree-zero packages — the effective
	// direct set, since pylock.toml records no project entry (poetry/pdm shape).
	root := rootNode(g, path)
	var attached int
	for i := range pkgs {
		p := &pkgs[i]
		if p.name == "" || p.version == "" {
			continue
		}
		id := idOf(p)
		if indeg[id] > 0 {
			continue // reached transitively
		}
		g.AddEdge(root.ID, id, graph.EdgeDependsOn)
		attached++
		if n := g.Get(id); n != nil {
			n.Direct = true
		}
	}
	if attached == 0 { // pure cycle / self-referential: never leave the tree empty
		for i := range pkgs {
			p := &pkgs[i]
			if p.name == "" || p.version == "" {
				continue
			}
			g.AddEdge(root.ID, idOf(p), graph.EdgeDependsOn)
			if n := g.Get(idOf(p)); n != nil {
				n.Direct = true
			}
		}
	}

	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["pypi.direct_attribution"] = "in-degree-zero"
	if lockVersion != "" && lockVersion != pylockVersionSupported {
		root.Attr["pypi.pylock_format"] = lockVersion
	}

	// The decisive pylock fact: if the locker recorded NO dependency edges (the
	// common case — the field is informational and usually omitted), the
	// transitive structure is unknown and every package hangs flat off the root.
	// That is presumed depth, not observed, so it is disclosed exactly as
	// Pipfile.lock / requirements.txt disclose it (D-24). When edges exist the
	// tree is real and this penalty is intentionally NOT set.
	if edgeCount == 0 {
		root.Attr[graph.AttrFlatResolution] = "pypi"
	}

	attachUnrooted(g, root.ID) // pull any cycle-only component under the root
	assignDepths(g, root.ID)
	return g, nil
}

// scanPylock walks the file once, returning the top-level lock-version ("" if
// absent) and the [[packages]] tables. Line scanner, not a TOML parser.
func scanPylock(raw []byte) (lockVersion string, pkgs []pylockPackage) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20) // hash / url lines are long

	inPreamble := true
	var cur *pylockPackage
	// section: "" (package scope) | vcs | directory | archive | sdist | wheels |
	// dependencies | skip (attestation-identities, tool, or a foreign table)
	section := ""
	var curDep *uvDep // active [[packages.dependencies]] sub-table entry

	// Multi-line inline dependency array state (uv shape reuse).
	var arrayBuf []uvDep
	var arrayCommit func([]uvDep)

	flush := func() {
		if cur != nil {
			pkgs = append(pkgs, *cur)
			cur = nil
		}
		curDep = nil
	}

	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())
		if trimmed == "" {
			continue
		}

		if inPreamble {
			if strings.HasPrefix(trimmed, "lock-version = ") {
				lockVersion = unquote(strings.TrimPrefix(trimmed, "lock-version = "))
			}
			if trimmed == "[[packages]]" {
				inPreamble = false
			} else {
				continue
			}
		}

		// New package.
		if trimmed == "[[packages]]" {
			flush()
			cur = &pylockPackage{}
			section = ""
			arrayCommit = nil
			continue
		}

		// A foreign top-level table ([tool], [tool.x], …) ends the packages array.
		if strings.HasPrefix(trimmed, "[") &&
			!strings.HasPrefix(trimmed, "[[packages") && !strings.HasPrefix(trimmed, "[packages") {
			flush()
			section = "skip"
			continue
		}
		if cur == nil {
			continue
		}

		// Reading a multi-line inline dependency array.
		if arrayCommit != nil {
			if trimmed == "]" || trimmed == "]," {
				arrayCommit(arrayBuf)
				arrayBuf = nil
				arrayCommit = nil
				continue
			}
			if d, ok := parseUvDepEntry(trimmed); ok {
				arrayBuf = append(arrayBuf, d)
			}
			continue
		}

		// Section (sub-table) headers.
		switch {
		case trimmed == "[packages.vcs]":
			section = "vcs"
			continue
		case trimmed == "[packages.directory]":
			section = "directory"
			continue
		case trimmed == "[packages.archive]":
			section = "archive"
			continue
		case trimmed == "[packages.sdist]":
			section = "sdist"
			continue
		case trimmed == "[[packages.wheels]]":
			section = "wheels"
			continue
		case trimmed == "[[packages.dependencies]]":
			section = "dependencies"
			cur.deps = append(cur.deps, uvDep{})
			curDep = &cur.deps[len(cur.deps)-1]
			continue
		case strings.HasPrefix(trimmed, "[packages."), strings.HasPrefix(trimmed, "[[packages."):
			// attestation-identities, tool, or anything else we do not read.
			section = "skip"
			continue
		}

		switch section {
		case "skip":
			continue

		case "vcs":
			switch {
			case strings.HasPrefix(trimmed, "url = ") && cur.vcsRef == "":
				cur.vcsRef = unquote(strings.TrimPrefix(trimmed, "url = "))
			case strings.HasPrefix(trimmed, "path = ") && cur.vcsRef == "":
				cur.vcsRef = unquote(strings.TrimPrefix(trimmed, "path = "))
			case strings.HasPrefix(trimmed, "commit-id = ") && cur.vcsRef == "":
				cur.vcsRef = unquote(strings.TrimPrefix(trimmed, "commit-id = "))
			}

		case "directory":
			if strings.HasPrefix(trimmed, "path = ") {
				cur.dirPath = unquote(strings.TrimPrefix(trimmed, "path = "))
			}

		case "archive":
			switch {
			case strings.HasPrefix(trimmed, "url = ") && cur.archiveRef == "":
				cur.archiveRef = unquote(strings.TrimPrefix(trimmed, "url = "))
			case strings.HasPrefix(trimmed, "path = ") && cur.archiveRef == "":
				cur.archiveRef = unquote(strings.TrimPrefix(trimmed, "path = "))
			}

		case "sdist":
			switch {
			case strings.HasPrefix(trimmed, "url = ") && cur.sdistRef == "":
				cur.sdistRef = unquote(strings.TrimPrefix(trimmed, "url = "))
			case strings.HasPrefix(trimmed, "path = ") && cur.sdistRef == "":
				cur.sdistRef = unquote(strings.TrimPrefix(trimmed, "path = "))
			}

		case "wheels":
			switch {
			case strings.HasPrefix(trimmed, "url = ") && cur.wheelRef == "":
				cur.wheelRef = unquote(strings.TrimPrefix(trimmed, "url = "))
			case strings.HasPrefix(trimmed, "path = ") && cur.wheelRef == "":
				cur.wheelRef = unquote(strings.TrimPrefix(trimmed, "path = "))
			}

		case "dependencies":
			if curDep == nil {
				continue
			}
			switch {
			case strings.HasPrefix(trimmed, "name = "):
				curDep.name = unquote(strings.TrimPrefix(trimmed, "name = "))
			case strings.HasPrefix(trimmed, "version = "):
				curDep.version = unquote(strings.TrimPrefix(trimmed, "version = "))
			}

		default: // package scope
			switch {
			case strings.HasPrefix(trimmed, "name = "):
				cur.name = unquote(strings.TrimPrefix(trimmed, "name = "))
			case strings.HasPrefix(trimmed, "version = "):
				cur.version = unquote(strings.TrimPrefix(trimmed, "version = "))
			case strings.HasPrefix(trimmed, "marker = "):
				cur.marker = unquote(strings.TrimPrefix(trimmed, "marker = "))
			case strings.HasPrefix(trimmed, "index = "):
				cur.index = unquote(strings.TrimPrefix(trimmed, "index = "))
			case strings.HasPrefix(trimmed, "dependencies = "):
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "dependencies = "))
				if deps, done := inlineArray(rest); done {
					cur.deps = append(cur.deps, deps...)
				} else {
					p := cur
					arrayBuf = nil
					arrayCommit = func(b []uvDep) { p.deps = append(p.deps, b...) }
				}
			case strings.HasPrefix(trimmed, "sdist = "):
				cur.sdistRef = firstInlineURL(strings.TrimPrefix(trimmed, "sdist = "))
			case strings.HasPrefix(trimmed, "wheels = "):
				if u := firstInlineURL(strings.TrimPrefix(trimmed, "wheels = ")); u != "" && cur.wheelRef == "" {
					cur.wheelRef = u
				}
			}
		}
	}
	flush()
	return lockVersion, pkgs
}

// firstInlineURL pulls the first `url = "..."` (or path) out of an inline table
// or inline array of tables, e.g. `{ url = "x", hashes = {...} }` or
// `[ { url = "a" }, { url = "b" } ]`. Returns "" if none is present on the line.
// It extracts only the quoted token, so trailing keys (hashes, size, …) on the
// same line are not swept into the value.
func firstInlineURL(rest string) string {
	rest = strings.TrimSpace(rest)
	best := -1
	for _, key := range []string{"url = ", "path = ", "url=", "path="} {
		if i := strings.Index(rest, key); i >= 0 && (best < 0 || i < best) {
			best = i + len(key)
		}
	}
	if best < 0 {
		return ""
	}
	return firstQuoted(rest[best:])
}

// firstQuoted returns the first single- or double-quoted string in s (or a bare
// token up to the next delimiter if unquoted).
func firstQuoted(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if q := s[0]; q == '\'' || q == '"' {
		if j := strings.IndexByte(s[1:], q); j >= 0 {
			return s[1 : 1+j]
		}
		return ""
	}
	if end := strings.IndexAny(s, ", }]"); end >= 0 {
		return s[:end]
	}
	return s
}

func truncatePylock(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
