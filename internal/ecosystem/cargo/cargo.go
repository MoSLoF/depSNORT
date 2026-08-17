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
	deps    []string
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
				// Dependencies can be "name", "name version", or
				// "name version (source)". We only need the name.
				parts := strings.Fields(dep)
				if len(parts) > 0 {
					cur.deps = append(cur.deps, parts[0])
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
				for _, d := range strings.Split(inner, ",") {
					dep := strings.Trim(strings.TrimSpace(d), `"`)
					if dep != "" {
						parts := strings.Fields(dep)
						if len(parts) > 0 {
							cur.deps = append(cur.deps, parts[0])
						}
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

	// Build nodes. Track by "name version" for deduplication (Cargo allows
	// multiple versions of the same crate).
	type key struct{ name, version string }
	byKey := map[key]string{}
	byName := map[string][]string{} // name -> [node IDs] for dep resolution

	for i, e := range entries {
		if e.name == "" || e.version == "" {
			continue
		}
		if i == 0 && e.name == root.Name {
			byKey[key{e.name, e.version}] = root.ID
			byName[e.name] = append(byName[e.name], root.ID)
			continue
		}
		id := purl.NewCargo(e.name, e.version).String()
		attr := map[string]string{"cargo.source": cargoLockName}
		if e.source != "" {
			attr["cargo.registry"] = e.source
		}
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "cargo", Name: e.name, Version: e.version,
			Attr: attr,
		})
		class, ref := classifySource(e.source)
		n.SetSource(class, ref)
		byKey[key{e.name, e.version}] = id
		byName[e.name] = append(byName[e.name], id)
	}

	// Build edges.
	for _, e := range entries {
		fromID, ok := byKey[key{e.name, e.version}]
		if !ok {
			continue
		}
		for _, dep := range e.deps {
			// Try to resolve dependency. The dep string is just a name;
			// Cargo.lock usually only has one version per crate.
			targets := byName[dep]
			if len(targets) == 0 {
				continue
			}
			for _, toID := range targets {
				if toID != fromID {
					g.AddEdge(fromID, toID, graph.EdgeDependsOn)
				}
			}
		}
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
