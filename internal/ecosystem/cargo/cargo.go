// Package cargo is the Cargo (Rust) ecosystem adapter. It parses Cargo.lock
// and builds the dependency graph.
//
// Install-time attack vector: crates with a build.rs file run it at compile
// time. The build script can execute arbitrary code, download files, and
// generate source. proc-macro crates also execute at compile time.
//
// Nothing here installs or executes anything (Decision D-04).
package cargo

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// Adapter implements ecosystem.Adapter for Cargo/Rust.
type Adapter struct{}

// New returns a Cargo adapter.
func New() *Adapter { return &Adapter{} }

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "cargo" }

const cargoLockName = "Cargo.lock"

// Detect implements ecosystem.Adapter.
func (*Adapter) Detect(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return fileExists(filepath.Join(path, cargoLockName))
	}
	return filepath.Base(path) == cargoLockName
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Resolve implements ecosystem.Adapter.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	file := path
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cargo: %w", err)
	}
	if info.IsDir() {
		file = filepath.Join(path, cargoLockName)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("cargo: reading %s: %w", cargoLockName, err)
	}
	return parseCargoLock(path, raw)
}

type cargoEntry struct {
	name    string
	version string
	source  string
	deps    []cargoDep
}

// cargoDep is one entry from a [[package]] dependencies list.
//
// Cargo writes the MINIMUM needed to disambiguate: "name" when the name is
// unique in the lock, "name version" when several versions are present, and
// "name version (source)" when the same name+version exists from more than one
// source. Keeping only the name — which this parser used to do — throws away
// exactly the information Cargo added because it was needed (finding
// DS-REV-02).
// cargoKey identifies one locked package. Cargo allows several versions of the
// same crate AND the same version from several sources, so neither the name nor
// the name+version pair is an identity on its own.
type cargoKey struct{ name, version, source string }

type cargoDep struct {
	name    string
	version string // empty when the lock did not need to disambiguate
	source  string // empty unless the lock qualified by source too
}

// parseDepSpec splits a dependency string into its name, version, and source.
func parseDepSpec(spec string) cargoDep {
	// The source, when present, is parenthesized and always last.
	var source string
	if i := strings.IndexByte(spec, '('); i >= 0 {
		if j := strings.LastIndexByte(spec, ')'); j > i {
			source = strings.TrimSpace(spec[i+1 : j])
		}
		spec = strings.TrimSpace(spec[:i])
	}
	fields := strings.Fields(spec)
	d := cargoDep{}
	if len(fields) > 0 {
		d.name = fields[0]
	}
	if len(fields) > 1 {
		d.version = fields[1]
	}
	d.source = source
	return d
}

// parseCargoLock parses a Cargo.lock file. The format is a subset of TOML with
// a regular structure that can be parsed line-by-line without a full TOML
// parser (D-10).
//
// Format:
//
//	[[package]]
//	name = "serde"
//	version = "1.0.188"
//	source = "registry+https://github.com/rust-lang/crates.io-index"
//	dependencies = [
//	 "serde_derive",
//	]
func parseCargoLock(path string, raw []byte) (*graph.Graph, error) {
	g := graph.New()

	var entries []cargoEntry
	var cur *cargoEntry
	inDeps := false

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "[[package]]" {
			entries = append(entries, cargoEntry{})
			cur = &entries[len(entries)-1]
			inDeps = false
			continue
		}

		if cur == nil {
			continue
		}

		if inDeps {
			if trimmed == "]" {
				inDeps = false
				continue
			}
			dep := strings.Trim(trimmed, `",`)
			dep = strings.TrimSpace(dep)
			if dep != "" {
				if d := parseDepSpec(dep); d.name != "" {
					cur.deps = append(cur.deps, d)
				}
			}
			continue
		}

		if strings.HasPrefix(trimmed, "name = ") {
			cur.name = extractTOMLString(trimmed)
		} else if strings.HasPrefix(trimmed, "version = ") {
			cur.version = extractTOMLString(trimmed)
		} else if strings.HasPrefix(trimmed, "source = ") {
			cur.source = extractTOMLString(trimmed)
		} else if strings.HasPrefix(trimmed, "dependencies = [") {
			if strings.HasSuffix(trimmed, "]") {
				// Single-line dependencies = []
				inner := trimmed[len("dependencies = [") : len(trimmed)-1]
				for _, raw := range strings.Split(inner, ",") {
					dep := strings.Trim(strings.TrimSpace(raw), `"`)
					if dep == "" {
						continue
					}
					if d := parseDepSpec(dep); d.name != "" {
						cur.deps = append(cur.deps, d)
					}
				}
			} else {
				inDeps = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cargo: scanning %s: %w", cargoLockName, err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("cargo: %s contained no packages", cargoLockName)
	}

	// The first [[package]] in Cargo.lock is typically the project itself.
	root := rootNode(g, path, entries[0])

	// Build nodes, keyed by FULL identity: name, version, and source.
	//
	// A crate vendored from a git fork is different code from the registry
	// crate of the same name and version, so it is a different node — the
	// PURL carries the origin as a qualifier (purl.WithSource, D-42). Registry
	// crates keep bare PURLs, so dedupe across a workspace is unchanged for
	// everything that is not a fork.
	byKey := map[cargoKey]string{}      // (name, version, source) -> node ID
	byNV := map[string][]string{}       // "name\x00version" -> node IDs
	byName := map[string][]string{}     // name -> node IDs, for name-only deps
	unresolved := map[string][]string{} // parent node ID -> ambiguous dep names

	nv := func(name, version string) string { return name + "\x00" + version }

	for i, e := range entries {
		if e.name == "" || e.version == "" {
			continue
		}
		k := cargoKey{e.name, e.version, e.source}
		if i == 0 && e.name == root.Name {
			byKey[k] = root.ID
			byNV[nv(e.name, e.version)] = append(byNV[nv(e.name, e.version)], root.ID)
			byName[e.name] = append(byName[e.name], root.ID)
			continue
		}

		class, ref := classifySource(e.source)
		id := purl.NewCargo(e.name, e.version).WithSource(class, ref).String()

		// Two entries with the same name, version AND source are genuinely
		// indistinguishable — the only way to reach this is two path crates,
		// because Cargo.lock records no path for them. Nothing here can tell
		// them apart, so the node keeps its first-seen position and says its
		// provenance is unknown rather than asserting one of two answers.
		if prev, seen := byKey[k]; seen {
			if n := g.Get(prev); n != nil {
				n.SetSource(graph.SourceUnknown,
					"ambiguous: two lock entries share this identity with source "+
						firstNonEmpty(e.source, "(none recorded)"))
				n.Attr["cargo.source_collision"] = "true"
			}
			continue
		}

		attr := map[string]string{"cargo.source": cargoLockName}
		if e.source != "" {
			attr["cargo.registry"] = e.source
		}
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "cargo", Name: e.name, Version: e.version,
			Attr: attr,
		})
		n.SetSource(class, ref)
		byKey[k] = id
		byNV[nv(e.name, e.version)] = append(byNV[nv(e.name, e.version)], id)
		byName[e.name] = append(byName[e.name], id)
	}

	// Build edges by DEPENDENCY IDENTITY, not by name (finding DS-REV-02).
	//
	// This loop used to add an edge to every node sharing the dependency's
	// name. Cargo qualifies a dependency with a version precisely when several
	// versions are present, so the over-connection happened exactly in the case
	// the qualification exists to prevent: a lock selecting "dupe 1.0.0" while
	// also holding dupe 2.0.0 produced edges to BOTH. Every downstream
	// conclusion drawn from the graph — reachability, depth, direct vs
	// transitive, blast radius, the topology digest a baseline diff compares —
	// inherits that error silently.
	for _, e := range entries {
		fromID, ok := byKey[cargoKey{e.name, e.version, e.source}]
		if !ok {
			continue
		}
		for _, dep := range e.deps {
			toID, ok := resolveDep(dep, byKey, byNV, byName)
			if !ok {
				// Ambiguous: a bare name with more than one candidate. Cargo
				// does not normally emit this, so it means a hand-edited or
				// malformed lock. Disclose it as unresolved coverage rather
				// than guess — a guessed edge is indistinguishable from a real
				// one once it is in the graph (D-24).
				if len(byName[dep.name]) > 1 {
					unresolved[fromID] = appendUnique(unresolved[fromID], dep.name)
				}
				continue
			}
			if toID != fromID {
				g.AddEdge(fromID, toID, graph.EdgeDependsOn)
			}
		}
	}

	// Record ambiguity on the parent, through the same coverage keys every
	// other adapter uses, so it reaches Coverage.Degraded -> Incomplete() and
	// can fail a run under -fail-on-incomplete without a new concept.
	for nodeID, names := range unresolved {
		n := g.Get(nodeID)
		if n == nil {
			continue
		}
		sort.Strings(names)
		if n.Attr == nil {
			n.Attr = map[string]string{}
		}
		n.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
		n.Attr[graph.AttrUnresolvedCount] = strconv.Itoa(len(names))
	}

	// Mark direct dependencies (deps of root).
	for _, e := range g.SortedEdges() {
		if e.From == root.ID && e.Type == graph.EdgeDependsOn {
			if n := g.Get(e.To); n != nil {
				n.Direct = true
			}
		}
	}

	assignDepths(g, root.ID)
	return g, nil
}

// resolveDep maps one dependency spec onto exactly one node, or reports that it
// cannot be resolved unambiguously.
//
// Resolution is strictly most-specific-first, and never widens:
//
//  1. (name, version) when the lock qualified by version. A version-qualified
//     dependency names one package; if that exact pair is absent the dependency
//     is unresolvable, NOT an invitation to fall back to the name.
//  2. name alone, only when exactly one candidate carries that name.
//
// When the spec also carries a source, it must match the candidate's source —
// same name and version from a registry and from a git fork are different
// packages with different contents, and treating them as one defeats the
// provenance model (D-41) at the graph layer.
func resolveDep(dep cargoDep, byKey map[cargoKey]string,
	byNV, byName map[string][]string,
) (string, bool) {
	if dep.version != "" {
		if dep.source != "" {
			id, ok := byKey[cargoKey{dep.name, dep.version, dep.source}]
			return id, ok
		}
		// Version but no source: unique unless the same version exists from
		// several sources, in which case the lock would have qualified it.
		if ids := byNV[dep.name+"\x00"+dep.version]; len(ids) == 1 {
			return ids[0], true
		}
		return "", false
	}
	if ids := byName[dep.name]; len(ids) == 1 {
		return ids[0], true
	}
	return "", false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

func rootNode(g *graph.Graph, path string, first cargoEntry) *graph.Node {
	name := first.name
	if name == "" {
		name = filepath.Base(strings.TrimSuffix(filepath.Clean(path), string(filepath.Separator)))
		if name == "." || name == "" || name == cargoLockName {
			name = "rust-project"
		}
	}
	version := first.version
	if version == "" {
		version = "0.0.0"
	}
	id := purl.NewCargo(name, version).String()
	n := g.AddNode(&graph.Node{
		ID: id, Ecosystem: "cargo", Name: name, Version: version, Depth: 0,
	})
	g.MarkRoot(id)
	return n
}

// classifySource maps a Cargo.lock `source` value onto an ecosystem-neutral
// provenance class (Decision D-41).
//
// Cargo's encoding is unusually clean here, and the ABSENT case is the load-
// bearing one: Cargo.lock omits `source` entirely for path dependencies and
// workspace members. A crate with no source line is vendored — its code lives
// in the repository, it was never published to crates.io, and no advisory feed
// has ever seen it. That is precisely the crate a reviewer must read by hand,
// and before this it was indistinguishable from the 243 registry crates around
// it.
//
// `sparse+` is the newer protocol for the same thing as `registry+` and must
// classify identically; missing it would report every project on a sparse
// index as entirely unverifiable.
func classifySource(source string) (class, ref string) {
	s := strings.TrimSpace(source)
	if s == "" {
		// No source line: path dependency or workspace member.
		return graph.SourcePath, ""
	}
	switch {
	case strings.HasPrefix(s, "registry+"), strings.HasPrefix(s, "sparse+"):
		return graph.SourceRegistry, s
	case strings.HasPrefix(s, "git+"):
		return graph.SourceGit, s
	case strings.HasPrefix(s, "path+"):
		return graph.SourcePath, s
	}
	return graph.ClassifyRef(s), s
}

// extractTOMLString extracts the value from a simple `key = "value"` line.
func extractTOMLString(line string) string {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return ""
	}
	val := strings.TrimSpace(line[i+1:])
	return strings.Trim(val, `"'`)
}

func assignDepths(g *graph.Graph, rootID string) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeDependsOn {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	depth := map[string]int{rootID: 0}
	seen := map[string]bool{rootID: true}
	queue := []string{rootID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if !seen[next] {
				seen[next] = true
				depth[next] = depth[cur] + 1
				queue = append(queue, next)
			}
		}
	}
	for id, d := range depth {
		if n := g.Get(id); n != nil {
			n.Depth = d
		}
	}
	for k := range adj {
		sort.Strings(adj[k])
	}
}
