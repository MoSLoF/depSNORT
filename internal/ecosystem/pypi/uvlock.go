package pypi

// uv.lock support.
//
// uv.lock is a TOML lockfile emitted by Astral's `uv`. Like Cargo.lock it is a
// FULLY RESOLVED graph: every package appears once as a [[package]] table with
// an observed version, a source, artifact hashes, and — crucially — its own
// `dependencies` list. That last fact is what separates it from Pipfile.lock:
// uv.lock expresses inter-package edges, so depSNORT reconstructs the real
// transitive tree with real depths instead of hanging everything off the root
// (the D-24 flat-resolution penalty Pipfile.lock incurs does NOT apply here).
//
// Decision D-10 forbids third-party dependencies and the Go standard library
// ships no TOML parser, so this reader does exactly what internal/ecosystem/cargo
// already does for Cargo.lock (also TOML): a line scanner over the constrained,
// regular subset of TOML a lockfile actually uses — [[package]] table arrays,
// `key = "value"` scalars, inline `{ name = "x" }` tables, and `key = [ ... ]`
// arrays. It does not attempt general TOML.
//
// Versions read here are TruthObserved (the graph default): uv resolved and
// pinned them. That is the point of teaching depSNORT this format — on a
// uv-locked project the transitive closure stops being presumed (guessed by
// expansion) and becomes an attributed fact from the lockfile.

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

const uvLockName = "uv.lock"

// uvLockFormatSupported is the uv.lock top-level `version` this reader targets.
// A newer format is still parsed best-effort — the [[package]] shape has been
// stable — but the mismatch is disclosed on the root node so a reader knows the
// parse rests on a format assumption (disclose, don't invent).
const uvLockFormatSupported = 1

type uvDep struct {
	name    string
	version string // disambiguator, present only on forked/multi-version names
}

type uvPackage struct {
	name       string
	version    string
	sourceKind string // registry | git | path | url | ""(virtual/none)
	sourceRef  string
	editable   bool // source = { editable = "." } — the project itself
	virtual    bool // source = { virtual = "." }
	runtime    []uvDep
	devGroups  map[string][]uvDep
	extras     map[string][]uvDep
}

func parseUvLock(path string, raw []byte) (*graph.Graph, error) {
	format, pkgs := scanUvLock(raw)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("pypi: %s contained no [[package]] entries", uvLockName)
	}

	byName := map[string][]*uvPackage{}
	for i := range pkgs {
		p := &pkgs[i]
		byName[purl.NormalizePyPI(p.name)] = append(byName[purl.NormalizePyPI(p.name)], p)
	}

	g := graph.New()
	idOf := func(p *uvPackage) string { return purl.NewPyPI(p.name, p.version).String() }

	for i := range pkgs {
		p := &pkgs[i]
		if p.version == "" {
			continue // no identity to scan; disclosed on the depender below
		}
		n := g.AddNode(&graph.Node{
			ID:        idOf(p),
			Ecosystem: "pypi",
			Name:      purl.NormalizePyPI(p.name),
			Version:   p.version,
			Attr:      map[string]string{"pypi.source": uvLockName},
		})
		if p.sourceKind != "" {
			n.SetSource(p.sourceKind, p.sourceRef)
		}
	}

	root := selectUvRoot(g, pkgs, idOf)
	if root == nil {
		return nil, fmt.Errorf("pypi: %s declares no editable or virtual root project", uvLockName)
	}
	g.MarkRoot(root.ID)

	resolve := func(d uvDep) (id, reason string) {
		cands := byName[purl.NormalizePyPI(d.name)]
		switch {
		case len(cands) == 0:
			return "", d.name
		case len(cands) == 1 && cands[0].version != "":
			return idOf(cands[0]), ""
		default:
			for _, c := range cands {
				if c.version != "" && c.version == d.version {
					return idOf(c), ""
				}
			}
			if len(cands) == 1 {
				return "", d.name
			}
			return "", d.name + " (ambiguous:" + itoa(len(cands)) + ")"
		}
	}

	addEdges := func(fromID string, deps []uvDep, direct bool, section string) []string {
		var unresolved []string
		for _, d := range deps {
			id, reason := resolve(d)
			if id == "" {
				unresolved = append(unresolved, reason)
				continue
			}
			g.AddEdge(fromID, id, graph.EdgeDependsOn)
			if n := g.Get(id); n != nil {
				if direct {
					n.Direct = true
				}
				if section != "" {
					if n.Attr == nil {
						n.Attr = map[string]string{}
					}
					if _, ok := n.Attr["pypi.section"]; !ok {
						n.Attr["pypi.section"] = section
					}
				}
			}
		}
		return unresolved
	}

	var rootPkg *uvPackage
	for i := range pkgs {
		if idOf(&pkgs[i]) == root.ID {
			rootPkg = &pkgs[i]
			break
		}
	}

	var rootUnresolved []string
	if rootPkg != nil {
		rootUnresolved = append(rootUnresolved, addEdges(root.ID, rootPkg.runtime, true, "runtime")...)
		for _, grp := range sortedDepKeys(rootPkg.devGroups) { // OPU-13: dev deps are real install surface
			rootUnresolved = append(rootUnresolved, addEdges(root.ID, rootPkg.devGroups[grp], true, "dev:"+grp)...)
		}
		for _, ex := range sortedDepKeys(rootPkg.extras) {
			rootUnresolved = append(rootUnresolved, addEdges(root.ID, rootPkg.extras[ex], true, "extra:"+ex)...)
		}
	}

	for i := range pkgs {
		p := &pkgs[i]
		if p.version == "" || idOf(p) == root.ID {
			continue
		}
		if missing := addEdges(idOf(p), p.runtime, false, ""); len(missing) > 0 {
			markUnresolved(g.Get(idOf(p)), missing)
		}
	}
	if len(rootUnresolved) > 0 {
		markUnresolved(root, rootUnresolved)
	}

	if format != 0 && format != uvLockFormatSupported {
		if root.Attr == nil {
			root.Attr = map[string]string{}
		}
		root.Attr["pypi.uvlock_format"] = itoa(format)
	}

	// A marker-gated dependency can be the only inbound path to a package (e.g.
	// tomli, pulled only on python_version < 3.11); such a package is in the
	// locked closure but would float detached. Pull any such component under the
	// root so every locked package is reachable — consistent with the other
	// lockfile readers.
	attachUnrooted(g, root.ID)
	assignDepths(g, root.ID) // real edges -> real depths; no AttrFlatResolution
	return g, nil
}

// scanUvLock walks the file once, returning the preamble `version` (0 if none)
// and the [[package]] tables. Line scanner, not a TOML parser.
func scanUvLock(raw []byte) (format int, pkgs []uvPackage) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20) // wheel/hash lines are long

	inPreamble := true
	var cur *uvPackage
	section := "" // "" | "dev" | "extra" | "skip"

	// Multi-line array state: accumulate into arrayBuf, commit via arrayCommit
	// on the closing bracket. A closure is used so map destinations (which
	// cannot be addressed by pointer) commit correctly.
	var arrayBuf []uvDep
	var arrayCommit func([]uvDep)

	flush := func() {
		if cur != nil {
			pkgs = append(pkgs, *cur)
			cur = nil
		}
	}
	openArray := func(commit func([]uvDep)) {
		arrayBuf = nil
		arrayCommit = commit
	}

	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())

		if inPreamble {
			if strings.HasPrefix(trimmed, "version = ") {
				format = atoiSafe(unquote(strings.TrimPrefix(trimmed, "version = ")))
			}
			if trimmed == "[[package]]" {
				inPreamble = false
			} else {
				continue
			}
		}

		if trimmed == "[[package]]" {
			flush()
			cur = &uvPackage{devGroups: map[string][]uvDep{}, extras: map[string][]uvDep{}}
			section = ""
			arrayCommit = nil
			continue
		}
		if cur == nil {
			continue
		}

		// Reading a multi-line array of dep entries.
		if arrayCommit != nil {
			if trimmed == "]" {
				arrayCommit(arrayBuf)
				arrayCommit = nil
				continue
			}
			if d, ok := parseUvDepEntry(trimmed); ok {
				arrayBuf = append(arrayBuf, d)
			}
			continue
		}

		switch {
		case trimmed == "[package.dev-dependencies]":
			section = "dev"
			continue
		case trimmed == "[package.optional-dependencies]":
			section = "extra"
			continue
		case strings.HasPrefix(trimmed, "[package."), strings.HasPrefix(trimmed, "[[package."):
			section = "skip"
			continue
		}
		if section == "skip" {
			continue
		}

		if section == "" {
			switch {
			case strings.HasPrefix(trimmed, "name = "):
				cur.name = unquote(strings.TrimPrefix(trimmed, "name = "))
			case strings.HasPrefix(trimmed, "version = "):
				cur.version = unquote(strings.TrimPrefix(trimmed, "version = "))
			case strings.HasPrefix(trimmed, "source = "):
				parseUvSource(cur, strings.TrimPrefix(trimmed, "source = "))
			case strings.HasPrefix(trimmed, "dependencies = "):
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "dependencies = "))
				if deps, done := inlineArray(rest); done {
					cur.runtime = append(cur.runtime, deps...)
				} else {
					p := cur
					openArray(func(b []uvDep) { p.runtime = append(p.runtime, b...) })
				}
			}
			continue
		}

		// dev / extra sub-tables: `group = [ ... ]`
		if i := strings.Index(trimmed, " = ["); i > 0 {
			key := strings.TrimSpace(trimmed[:i])
			dst := cur.devGroups
			if section == "extra" {
				dst = cur.extras
			}
			rest := strings.TrimSpace(trimmed[i+len(" ="):])
			if deps, done := inlineArray(rest); done {
				dst[key] = append(dst[key], deps...)
			} else {
				d := dst
				k := key
				openArray(func(b []uvDep) { d[k] = append(d[k], b...) })
			}
		}
	}
	flush()
	return format, pkgs
}

// inlineArray handles single-line array forms: `[]`, `[{...}, {...}]`. Returns
// (deps, true) if the array closed on this line; (nil, false) if it is a bare
// `[` opener the caller must keep reading.
func inlineArray(rest string) ([]uvDep, bool) {
	rest = strings.TrimSpace(rest)
	if rest == "[]" {
		return nil, true
	}
	if rest == "[" {
		return nil, false
	}
	if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
		var out []uvDep
		for _, part := range splitTopLevel(rest[1:len(rest)-1], ',') {
			if d, ok := parseUvDepEntry(part); ok {
				out = append(out, d)
			}
		}
		return out, true
	}
	return nil, false
}

// parseUvDepEntry reads one `{ name = "x", version = "1.2.3", ... }` inline
// table (trailing comma tolerated). Only name and version feed the graph.
func parseUvDepEntry(s string) (uvDep, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ","))
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return uvDep{}, false
	}
	var d uvDep
	for _, kv := range splitTopLevel(s[1:len(s)-1], ',') {
		kv = strings.TrimSpace(kv)
		switch {
		case strings.HasPrefix(kv, "name = "):
			d.name = unquote(strings.TrimPrefix(kv, "name = "))
		case strings.HasPrefix(kv, "version = "):
			d.version = unquote(strings.TrimPrefix(kv, "version = "))
		}
	}
	if d.name == "" {
		return uvDep{}, false
	}
	return d, true
}

func parseUvSource(p *uvPackage, rest string) {
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "{") || !strings.HasSuffix(rest, "}") {
		return
	}
	for _, kv := range splitTopLevel(rest[1:len(rest)-1], ',') {
		kv = strings.TrimSpace(kv)
		eq := strings.Index(kv, " = ")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(kv[:eq])
		val := unquote(strings.TrimSpace(kv[eq+3:]))
		switch key {
		case "registry":
			p.sourceKind, p.sourceRef = graph.SourceRegistry, val
		case "git":
			p.sourceKind, p.sourceRef = graph.SourceGit, val
		case "url":
			p.sourceKind, p.sourceRef = graph.SourceURL, val
		case "path", "directory":
			p.sourceKind, p.sourceRef = graph.SourcePath, val
		case "editable":
			p.sourceKind, p.sourceRef, p.editable = graph.SourcePath, val, true
		case "virtual":
			p.virtual = true
		}
	}
}

func selectUvRoot(g *graph.Graph, pkgs []uvPackage, idOf func(*uvPackage) string) *graph.Node {
	for i := range pkgs {
		if (pkgs[i].editable || pkgs[i].virtual) && pkgs[i].version != "" {
			return g.Get(idOf(&pkgs[i]))
		}
	}
	if len(pkgs) == 1 && pkgs[0].version != "" {
		return g.Get(idOf(&pkgs[0]))
	}
	return nil
}

func markUnresolved(n *graph.Node, names []string) {
	if n == nil || len(names) == 0 {
		return
	}
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	sort.Strings(names)
	n.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
	n.Attr[graph.AttrUnresolvedCount] = itoa(len(names))
}

func unquote(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ","))
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// splitTopLevel splits on sep, ignoring separators inside quotes or braces.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	inStr := false
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			if c == q {
				inStr = false
			}
		case c == '"' || c == '\'':
			inStr, q = true, c
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func sortedDepKeys(m map[string][]uvDep) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func atoiSafe(s string) int {
	s = strings.TrimSpace(s)
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
