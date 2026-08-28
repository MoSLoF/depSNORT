// Package clojure is the Clojure ecosystem adapter (D-162). It statically
// parses Leiningen project.clj and tools.deps deps.edn manifests and resolves
// their DIRECT dependencies to Maven coordinates — the coordinate system both
// tools share, and the one OSV indexes ("Maven"). Nodes therefore carry
// Ecosystem "maven" and pkg:maven PURLs: the manifest family is Clojure, but
// the packages live in Maven/Clojars registries and advisory data speaks
// Maven.
//
// What this adapter claims and what it does not (D-24 honesty):
//   - A direct dependency with a literal version IS an observed pin — both
//     tools fetch exactly the stated version for direct deps — so those nodes
//     enter the graph as facts, not presumptions.
//   - Neither manifest format records the transitive closure, so every root
//     resolves flat (AttrFlatResolution): a format limitation, disclosed, not
//     a scan defect. The -expand tier can deepen it from deps.dev.
//   - A version that is not a literal pin (a range, RELEASE/LATEST, a symbol
//     evaluated at build time) is declared-but-unresolved, never guessed.
//   - Git and :local/root coordinates are recorded with their source class —
//     no registry coordinate, no advisory coverage, disclosed like any other
//     non-registry source.
//
// Maven dependency FETCH executes nothing — resolution downloads jars, and no
// install-time hook runs on the consumer's machine (build-time plugins are a
// different surface, out of scope here) — so this adapter's empty install
// surface is a fact about the ecosystem, not an extraction gap.
//
// Nothing here installs or executes anything (Decision D-04).
package clojure

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// Adapter implements ecosystem.Adapter for Clojure (Leiningen + tools.deps).
type Adapter struct{}

// New returns a Clojure adapter.
func New() *Adapter { return &Adapter{} }

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "clojure" }

const (
	projectCljName = "project.clj"
	depsEdnName    = "deps.edn"
)

// Detect implements ecosystem.Adapter. A project.clj or deps.edn that declares
// at least one dependency claims the directory — the same declares-something
// bar the Gemfile path uses (OPU-16), so a dependency-less manifest stays
// legitimately unclaimed rather than erroring through Resolve.
func (*Adapter) Detect(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return projectCljDeclares(filepath.Join(path, projectCljName)) ||
			depsEdnDeclares(filepath.Join(path, depsEdnName))
	}
	switch filepath.Base(path) {
	case projectCljName:
		return projectCljDeclares(path)
	case depsEdnName:
		return depsEdnDeclares(path)
	}
	return false
}

func projectCljDeclares(p string) bool {
	raw, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	deps, unparsed, _, _ := parseProjectClj(string(raw))
	return len(deps) > 0 || unparsed > 0
}

func depsEdnDeclares(p string) bool {
	raw, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	deps, unparsed := parseDepsEdn(string(raw))
	return len(deps) > 0 || unparsed > 0
}

// Resolve implements ecosystem.Adapter. When a directory carries both
// manifests, both are read into one graph under one root — they describe the
// same project's fetches, and dropping either would be the silent-coverage
// shape D-59 exists to prevent.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("clojure: %w", err)
	}

	type manifest struct {
		name string
		raw  string
	}
	var manifests []manifest
	read := func(p string) error {
		raw, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("clojure: reading %s: %w", filepath.Base(p), err)
		}
		manifests = append(manifests, manifest{name: filepath.Base(p), raw: string(raw)})
		return nil
	}
	dir := path
	if info.IsDir() {
		for _, name := range []string{projectCljName, depsEdnName} {
			p := filepath.Join(path, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				if err := read(p); err != nil {
					return nil, err
				}
			}
		}
	} else {
		dir = filepath.Dir(path)
		if err := read(path); err != nil {
			return nil, err
		}
	}
	if len(manifests) == 0 {
		return nil, fmt.Errorf("clojure: no %s or %s at %s", projectCljName, depsEdnName, path)
	}

	var (
		deps                  []dep
		unparsed              int
		rootName, rootVersion string
		sources               []string
	)
	for _, m := range manifests {
		switch m.name {
		case projectCljName:
			d, u, n, v := parseProjectClj(m.raw)
			deps, unparsed = append(deps, d...), unparsed+u
			rootName, rootVersion = n, v
		case depsEdnName:
			d, u := parseDepsEdn(m.raw)
			deps, unparsed = append(deps, d...), unparsed+u
		}
		sources = append(sources, m.name)
	}

	g := graph.New()
	root := rootNode(g, dir, rootName, rootVersion)
	root.Attr["clojure.source"] = strings.Join(sources, ",")

	// Dedupe on the full coordinate@version: the same dep declared in a
	// profile and the top level is one fact; the same coordinate at two
	// versions is two facts, both kept.
	var (
		declared   []graph.DeclaredDep
		unresolved []string
		seenNode   = map[string]bool{}
		seenDecl   = map[string]bool{}
	)
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].coordinate() != deps[j].coordinate() {
			return deps[i].coordinate() < deps[j].coordinate()
		}
		return deps[i].version < deps[j].version
	})
	for _, d := range deps {
		if !seenDecl[d.coordinate()] {
			seenDecl[d.coordinate()] = true
			declared = append(declared, graph.DeclaredDep{Name: d.coordinate(), Constraint: firstNonEmpty(d.version, d.constraint)})
		}
		if d.version == "" && d.source == graph.SourceRegistry {
			// Declared with no pin this reader may claim: disclosed, never
			// presumed here (the expansion tier presumes, and labels it).
			if !contains(unresolved, d.coordinate()) {
				unresolved = append(unresolved, d.coordinate())
			}
			continue
		}
		id := purl.NewMaven(d.group, d.artifact, d.version).String()
		if seenNode[id] {
			continue
		}
		seenNode[id] = true
		n := &graph.Node{
			ID:        id,
			Ecosystem: "maven",
			Name:      d.coordinate(),
			Version:   d.version,
			Direct:    true,
			Depth:     1,
			Attr:      map[string]string{graph.AttrSourceClass: d.source},
		}
		if d.ref != "" {
			n.Attr[graph.AttrSourceRef] = d.ref
		}
		g.AddNode(n)
		g.AddEdge(root.ID, id, graph.EdgeDependsOn)
	}
	for i := 0; i < unparsed; i++ {
		// An entry the reader could not read at all still degrades coverage —
		// a shape we cannot name gets a placeholder, not silence.
		unresolved = append(unresolved, fmt.Sprintf("unparsed-entry#%d", i+1))
	}

	root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(declared)
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		root.Attr[graph.AttrUnresolved] = strings.Join(unresolved, ",")
		root.Attr[graph.AttrUnresolvedCount] = fmt.Sprintf("%d", len(unresolved))
	}
	// Neither manifest format records inter-package relationships: one layer
	// deep by construction, a property of the format, disclosed as such.
	root.Attr[graph.AttrFlatResolution] = "maven"
	return g, nil
}

// rootNode builds the project root, named from defproject when project.clj
// states an identity, else from the directory.
func rootNode(g *graph.Graph, dir, name, version string) *graph.Node {
	if name == "" {
		name = filepath.Base(filepath.Clean(dir))
		if name == "." || name == "" || name == string(filepath.Separator) {
			name = "clojure-project"
		}
	}
	if version == "" {
		version = "0.0.0"
	}
	group, artifact, ok := splitCoord(name)
	if !ok {
		group, artifact = "", "clojure-project"
	} else if group == artifact && !strings.Contains(name, "/") {
		group = "" // a bare project name is not a group:artifact claim
	}
	id := purl.NewMaven(group, artifact, version).String()
	n := g.AddNode(&graph.Node{
		ID: id, Ecosystem: "maven", Name: name, Version: version, Depth: 0,
		Attr: map[string]string{},
	})
	g.MarkRoot(id)
	return n
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
