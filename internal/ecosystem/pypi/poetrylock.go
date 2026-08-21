package pypi

// poetry.lock support — Tier 2 of the PyPI TOML-lockfile family (OPU-29).
//
// Same root cause and same remedy as uv.lock (see uvlock.go): poetry.lock is
// TOML, the Go stdlib has no TOML parser, and Decision D-10 forbids importing
// one, so this is a line scanner over the constrained subset a lockfile uses. It
// reuses the shared helpers in uvlock.go (unquote, splitTopLevel, markUnresolved)
// and the package-wide assignDepths / itoa — the separation is by reader, the
// primitives are shared.
//
// poetry.lock differs from uv.lock in three ways that shape this reader:
//
//  1. No root project. uv.lock carries the editable "." project; poetry.lock
//     does not — the root's direct deps live in pyproject.toml. This reader is
//     lock-only, so it SYNTHESIZES a root and attaches it to the in-degree-zero
//     packages (those nothing else depends on = the effective top level). That
//     attribution is a documented heuristic: a sibling pyproject.toml would
//     sharpen direct-vs-transitive, and is a candidate follow-up. Coverage is
//     unaffected either way — every locked package is a node and is scanned.
//  2. [package.dependencies] is a sub-table of `name = "constraint"` (or
//     `name = { version = "...", ... }`) lines, not uv's inline `{ name = }`
//     arrays. The KEY is the dependency name; the constraint is metadata this
//     reader does not need (the resolved version is the depended package's own
//     [[package]] entry).
//  3. Group membership is a `groups = ["main", ...]` field per package rather
//     than dev-dependency sub-tables. "main" is runtime; anything else is a
//     dev/optional group and tagged as such (OPU-13: still real install surface).
//
// Versions are TruthObserved: poetry resolved and pinned them.

import (
	"bufio"
	"fmt"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

const poetryLockName = "poetry.lock"

// poetryLockFormatSupported is the [metadata] lock-version this reader targets.
// A newer lock-version is parsed best-effort and the mismatch disclosed on the
// synthesized root (disclose, don't invent).
const poetryLockFormatSupported = "2.1"

type poetryPackage struct {
	name       string
	version    string
	groups     []string
	sourceKind string // registry(default) | git | url | path
	sourceRef  string
	deps       []string // dependency names (edges)
}

func parsePoetryLock(path string, raw []byte) (*graph.Graph, error) {
	lockVersion, pkgs := scanPoetryLock(raw)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("pypi: %s contained no [[package]] entries", poetryLockName)
	}

	g := graph.New()
	idOf := func(p *poetryPackage) string { return purl.NewPyPI(p.name, p.version).String() }

	// Nodes: one per locked package, observed version, provenance.
	for i := range pkgs {
		p := &pkgs[i]
		if p.version == "" {
			continue
		}
		n := g.AddNode(&graph.Node{
			ID:        idOf(p),
			Ecosystem: "pypi",
			Name:      purl.NormalizePyPI(p.name),
			Version:   p.version,
			Attr:      map[string]string{"pypi.source": poetryLockName},
		})
		if p.sourceKind != "" {
			n.SetSource(p.sourceKind, p.sourceRef)
		} else {
			// poetry omits a source table for registry (PyPI) packages; record
			// it positively so the coverage layer treats them as advisory-queryable.
			n.SetSource(graph.SourceRegistry, "https://pypi.org/simple")
		}
	}

	byName := map[string]string{} // normalized name -> node ID
	groupOf := map[string][]string{}
	for i := range pkgs {
		p := &pkgs[i]
		if p.version == "" {
			continue
		}
		key := purl.NormalizePyPI(p.name)
		byName[key] = idOf(p)
		groupOf[key] = p.groups
	}

	// Inter-package edges: the real transitive graph.
	indeg := map[string]int{}
	for i := range pkgs {
		p := &pkgs[i]
		if p.version == "" {
			continue
		}
		fromID := idOf(p)
		var missing []string
		for _, dep := range p.deps {
			toID, ok := byName[purl.NormalizePyPI(dep)]
			if !ok {
				missing = append(missing, dep)
				continue
			}
			g.AddEdge(fromID, toID, graph.EdgeDependsOn)
			indeg[toID]++
		}
		if len(missing) > 0 {
			markUnresolved(g.Get(fromID), missing)
		}
	}

	// Synthesize the root and attach it to the in-degree-zero packages — the
	// effective direct set, since poetry.lock records no project entry.
	root := rootNode(g, path)
	var attached int
	for i := range pkgs {
		p := &pkgs[i]
		if p.version == "" {
			continue
		}
		id := idOf(p)
		if indeg[id] > 0 {
			continue // depended upon by something else -> reached transitively
		}
		g.AddEdge(root.ID, id, graph.EdgeDependsOn)
		attached++
		if n := g.Get(id); n != nil {
			n.Direct = true
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			if _, ok := n.Attr["pypi.section"]; !ok {
				n.Attr["pypi.section"] = poetrySection(groupOf[purl.NormalizePyPI(p.name)])
			}
		}
	}

	// Record the direct-attribution heuristic so a reader knows root edges are
	// inferred from in-degree, not read from a project manifest.
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["pypi.direct_attribution"] = "in-degree-zero"
	if lockVersion != "" && lockVersion != poetryLockFormatSupported {
		root.Attr["pypi.poetrylock_format"] = lockVersion
	}

	// A lock where every package is depended upon by another (a pure cycle, or a
	// single self-referential entry) would attach nothing; fall back to the
	// whole set so the tree is never empty.
	if attached == 0 {
		for i := range pkgs {
			if pkgs[i].version != "" {
				g.AddEdge(root.ID, idOf(&pkgs[i]), graph.EdgeDependsOn)
				if n := g.Get(idOf(&pkgs[i])); n != nil {
					n.Direct = true
				}
			}
		}
	}

	attachUnrooted(g, root.ID) // pull cycle-only components under the root
	assignDepths(g, root.ID)   // real edges -> real depths; no flat-resolution penalty
	return g, nil
}

// scanPoetryLock walks the file once: returns the [metadata] lock-version (""
// if absent) and the [[package]] tables.
func scanPoetryLock(raw []byte) (lockVersion string, pkgs []poetryPackage) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)

	var cur *poetryPackage
	section := "" // "" | deps | extras | source | skip
	inMetadata := false
	skipArray := false // inside a multi-line [ ... ] value we do not descend into

	flush := func() {
		if cur != nil {
			pkgs = append(pkgs, *cur)
			cur = nil
		}
	}

	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if skipArray {
			if trimmed == "]" || strings.HasSuffix(trimmed, "]") {
				skipArray = false
			}
			continue
		}

		if trimmed == "[[package]]" {
			flush()
			cur = &poetryPackage{}
			section = ""
			inMetadata = false
			continue
		}
		if trimmed == "[metadata]" {
			flush()
			inMetadata = true
			section = ""
			continue
		}
		if inMetadata {
			if strings.HasPrefix(trimmed, "lock-version = ") {
				lockVersion = unquote(strings.TrimPrefix(trimmed, "lock-version = "))
			}
			continue
		}
		if cur == nil {
			continue
		}

		switch {
		case trimmed == "[package.dependencies]":
			section = "deps"
			continue
		case trimmed == "[package.extras]":
			section = "extras"
			continue
		case trimmed == "[package.source]":
			section = "source"
			continue
		case strings.HasPrefix(trimmed, "[package."), strings.HasPrefix(trimmed, "[["):
			section = "skip"
			continue
		}

		switch section {
		case "":
			switch {
			case strings.HasPrefix(trimmed, "name = "):
				cur.name = unquote(strings.TrimPrefix(trimmed, "name = "))
			case strings.HasPrefix(trimmed, "version = "):
				cur.version = unquote(strings.TrimPrefix(trimmed, "version = "))
			case strings.HasPrefix(trimmed, "groups = "):
				cur.groups = parseStringList(strings.TrimPrefix(trimmed, "groups = "))
			case strings.HasPrefix(trimmed, "files = ") && strings.HasSuffix(trimmed, "["):
				skipArray = true
			}
		case "deps":
			// `name = ...` — the key is the dependency name; value is metadata.
			if eq := strings.Index(trimmed, " = "); eq > 0 {
				name := strings.TrimSpace(trimmed[:eq])
				cur.deps = append(cur.deps, name)
				if strings.HasSuffix(trimmed, "[") { // multi-line constraint array
					skipArray = true
				}
			}
		case "source":
			if eq := strings.Index(trimmed, " = "); eq > 0 {
				key := strings.TrimSpace(trimmed[:eq])
				val := unquote(strings.TrimSpace(trimmed[eq+3:]))
				switch key {
				case "type":
					switch val {
					case "git":
						cur.sourceKind = graph.SourceGit
					case "url":
						cur.sourceKind = graph.SourceURL
					case "directory", "file":
						cur.sourceKind = graph.SourcePath
					case "legacy":
						cur.sourceKind = graph.SourceRegistry
					}
				case "url":
					cur.sourceRef = val
				}
			}
		case "extras", "skip":
			// extras are optional install surface; not turned into edges in this
			// tier (documented limitation). Skip any multi-line array cleanly.
			if strings.HasSuffix(trimmed, "[") {
				skipArray = true
			}
		}
	}
	flush()
	return lockVersion, pkgs
}

// attachUnrooted guarantees every package node is reachable from the synthesized
// root. The in-degree-zero heuristic that seeds direct edges cannot reach a pure
// dependency CYCLE (every member has an in-edge from within the cycle, so none is
// in-degree-zero and none hangs off the root). Such a component would otherwise
// float at depth 0, misrepresenting the tree. This attaches one entry point per
// unreachable weakly-connected component in deterministic order (D-09/D-13) and
// lets the component's own edges define depth from there. Shared by the
// synthesized-root readers (poetry.lock, pdm.lock); uv.lock has an explicit root
// and does not need it.
func attachUnrooted(g *graph.Graph, rootID string) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeDependsOn {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	reach := map[string]bool{rootID: true}
	bfs := func(start string) {
		queue := []string{start}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, nx := range adj[cur] {
				if !reach[nx] {
					reach[nx] = true
					queue = append(queue, nx)
				}
			}
		}
	}
	bfs(rootID)
	for _, n := range g.SortedNodes() { // deterministic order
		if n.Kind == graph.KindPackage && n.ID != rootID && !reach[n.ID] {
			g.AddEdge(rootID, n.ID, graph.EdgeDependsOn)
			reach[n.ID] = true
			bfs(n.ID)
		}
	}
}

// poetrySection maps a package's group membership to a section tag: "main" is
// runtime, any other group is a dev/optional surface.
func poetrySection(groups []string) string {
	hasMain := false
	other := ""
	for _, g := range groups {
		if g == "main" {
			hasMain = true
		} else if other == "" {
			other = g
		}
	}
	if hasMain {
		return "runtime"
	}
	if other != "" {
		return "dev:" + other
	}
	return "runtime"
}

// parseStringList reads a single-line TOML array of quoted strings:
// `["main", "dev"]` -> ["main","dev"].
func parseStringList(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil
	}
	var out []string
	for _, part := range splitTopLevel(s[1:len(s)-1], ',') {
		if v := unquote(strings.TrimSpace(part)); v != "" {
			out = append(out, v)
		}
	}
	return out
}
