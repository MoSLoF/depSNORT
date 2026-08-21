package pypi

// pdm.lock support — Tier 3 of the PyPI TOML-lockfile family (OPU-29).
//
// Same root cause and remedy as uv.lock / poetry.lock (see uvlock.go): pdm.lock
// is TOML, the stdlib has no TOML parser, D-10 forbids importing one, so this is
// a line scanner over the lockfile subset. It reuses the package scanner
// primitives and follows poetry.lock's shape closely — pdm.lock, like poetry's,
// records no root project and tags packages with a `groups = [...]` field.
//
// The one structural difference is the dependency form: pdm writes
// `dependencies = ["idna>=2.8", "typing-extensions>=4.5; ...", ...]` — an array
// of PEP 508 requirement STRINGS, not uv's inline `{ name = }` tables nor
// poetry's [package.dependencies] sub-table. The dependency name is extracted
// with the existing internal/pep508 helper (reuse, not reinvention). pdm's
// runtime group is "default" (poetry uses "main").
//
// Versions are TruthObserved: pdm resolved and pinned them.

import (
	"bufio"
	"fmt"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
)

const pdmLockName = "pdm.lock"

// pdmLockFormatSupported is the [metadata] lock_version this reader targets. A
// newer lock_version is parsed best-effort and disclosed on the synthesized root.
const pdmLockFormatSupported = "4.5.1"

type pdmPackage struct {
	name    string
	version string
	groups  []string
	deps    []string // dependency NAMES (extracted from PEP 508 strings)
}

func parsePdmLock(path string, raw []byte) (*graph.Graph, error) {
	lockVersion, pkgs := scanPdmLock(raw)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("pypi: %s contained no [[package]] entries", pdmLockName)
	}

	g := graph.New()
	idOf := func(p *pdmPackage) string { return purl.NewPyPI(p.name, p.version).String() }

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
			Attr:      map[string]string{"pypi.source": pdmLockName},
		})
		// pdm.lock does not record a per-package source table for registry
		// packages; record registry positively so they stay advisory-queryable.
		n.SetSource(graph.SourceRegistry, "https://pypi.org/simple")
	}

	byName := map[string]string{}
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

	root := rootNode(g, path)
	var attached int
	for i := range pkgs {
		p := &pkgs[i]
		if p.version == "" || indeg[idOf(p)] > 0 {
			continue
		}
		id := idOf(p)
		g.AddEdge(root.ID, id, graph.EdgeDependsOn)
		attached++
		if n := g.Get(id); n != nil {
			n.Direct = true
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			if _, ok := n.Attr["pypi.section"]; !ok {
				n.Attr["pypi.section"] = pdmSection(groupOf[purl.NormalizePyPI(p.name)])
			}
		}
	}
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["pypi.direct_attribution"] = "in-degree-zero"
	if lockVersion != "" && lockVersion != pdmLockFormatSupported {
		root.Attr["pypi.pdmlock_format"] = lockVersion
	}
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
	assignDepths(g, root.ID)
	return g, nil
}

func scanPdmLock(raw []byte) (lockVersion string, pkgs []pdmPackage) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)

	var cur *pdmPackage
	inMetadata := false
	section := "" // "" | deps | skip
	skipArray := false

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

		if section == "deps" {
			if trimmed == "]" {
				section = ""
				continue
			}
			// each entry is a quoted PEP 508 requirement string
			s := unquote(trimmed)
			if name, _, _ := pep508.SplitSpecifier(s); name != "" {
				cur.deps = append(cur.deps, pep508.StripExtras(name))
			}
			continue
		}

		if trimmed == "[[package]]" {
			flush()
			cur = &pdmPackage{}
			inMetadata = false
			section = ""
			continue
		}
		if trimmed == "[metadata]" {
			flush()
			inMetadata = true
			section = ""
			continue
		}
		if strings.HasPrefix(trimmed, "[[metadata.") || strings.HasPrefix(trimmed, "[metadata.") {
			flush()
			inMetadata = true
			section = ""
			continue
		}
		if inMetadata {
			if strings.HasPrefix(trimmed, "lock_version = ") {
				lockVersion = unquote(strings.TrimPrefix(trimmed, "lock_version = "))
			}
			continue
		}
		if cur == nil {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "name = "):
			cur.name = unquote(strings.TrimPrefix(trimmed, "name = "))
		case strings.HasPrefix(trimmed, "version = "):
			cur.version = unquote(strings.TrimPrefix(trimmed, "version = "))
		case strings.HasPrefix(trimmed, "groups = "):
			cur.groups = parseStringList(strings.TrimPrefix(trimmed, "groups = "))
		case strings.HasPrefix(trimmed, "dependencies = ") && strings.HasSuffix(trimmed, "["):
			section = "deps"
		case strings.HasPrefix(trimmed, "files = ") && strings.HasSuffix(trimmed, "["):
			skipArray = true
		case strings.HasPrefix(trimmed, "[package."):
			skipArray = false // sub-tables (e.g. no standard ones carry edges); ignore scalars
		}
	}
	flush()
	return lockVersion, pkgs
}

// pdmSection maps pdm group membership to a section tag. pdm's runtime group is
// "default"; anything else is a dev/optional surface (OPU-13).
func pdmSection(groups []string) string {
	hasDefault := false
	other := ""
	for _, g := range groups {
		if g == "default" {
			hasDefault = true
		} else if other == "" {
			other = g
		}
	}
	if hasDefault {
		return "runtime"
	}
	if other != "" {
		return "dev:" + other
	}
	return "runtime"
}
