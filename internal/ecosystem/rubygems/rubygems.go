// Package rubygems is the RubyGems ecosystem adapter. It parses Gemfile.lock
// (Bundler's lockfile) and builds the dependency graph.
//
// Install-time attack vector: gems with native extensions compile via
// extconf.rb during `gem install`. That file runs arbitrary Ruby code.
//
// Nothing here installs or executes anything (Decision D-04).
package rubygems

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

// Adapter implements ecosystem.Adapter for RubyGems.
type Adapter struct{}

// New returns a RubyGems adapter.
func New() *Adapter { return &Adapter{} }

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "gem" }

const gemfileLockName = "Gemfile.lock"

// Detect implements ecosystem.Adapter.
func (*Adapter) Detect(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return fileExists(filepath.Join(path, gemfileLockName))
	}
	return filepath.Base(path) == gemfileLockName
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
		return nil, fmt.Errorf("gem: %w", err)
	}
	if info.IsDir() {
		file = filepath.Join(path, gemfileLockName)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("gem: reading %s: %w", gemfileLockName, err)
	}
	return parseGemfileLock(path, raw)
}

type gemEntry struct {
	name    string
	version string
	deps    []string
	// section and remote record WHERE the gem came from: Bundler groups specs
	// under GEM (a registry), GIT (a repository), or PATH (local source), and
	// names the origin on the section's `remote:` line. Both were parsed and
	// discarded before D-41 — a gem pinned to a git ref read exactly like a
	// rubygems.org gem to every stage downstream.
	section string
	remote  string
}

// parseGemfileLock parses a Bundler Gemfile.lock.
//
// Format:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actioncable (7.0.4)
//	      actionpack (= 7.0.4)
//	      activesupport (= 7.0.4)
//
//	PLATFORMS
//	  ruby
//
//	DEPENDENCIES
//	  rails (~> 7.0)
//
//	BUNDLED WITH
//	   2.3.26
func parseGemfileLock(path string, raw []byte) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, path)

	var (
		gems    []gemEntry
		directs = map[string]bool{}
		section string
		remote  string
		inSpecs bool
		curGem  *gemEntry
	)

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()

		// Section headers are unindented.
		if len(line) > 0 && line[0] != ' ' {
			trimmed := strings.TrimSpace(line)
			switch {
			case trimmed == "GEM" || trimmed == "GIT" || trimmed == "PATH":
				section = trimmed
			case trimmed == "PLATFORMS":
				section = "PLATFORMS"
			case trimmed == "DEPENDENCIES":
				section = "DEPENDENCIES"
			case trimmed == "BUNDLED WITH":
				section = "BUNDLED"
			default:
				section = trimmed
			}
			inSpecs = false
			remote = ""
			curGem = nil
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		switch section {
		case "GEM", "GIT", "PATH":
			if trimmed == "specs:" {
				inSpecs = true
				continue
			}
			if !inSpecs {
				// The section preamble names the origin: "remote: <url>" for
				// GEM/GIT, "remote: ." for PATH.
				if r, ok := strings.CutPrefix(trimmed, "remote:"); ok {
					remote = strings.TrimSpace(r)
				}
				continue
			}
			indent := countIndent(line)
			if indent == 4 {
				// Package entry: "    name (version)"
				name, version := parseGemSpec(trimmed)
				if name != "" && version != "" {
					gems = append(gems, gemEntry{
						name: name, version: version,
						section: section, remote: remote,
					})
					curGem = &gems[len(gems)-1]
				} else {
					curGem = nil
				}
			} else if indent >= 6 && curGem != nil {
				// Dependency of current gem: "      dep-name (constraint)"
				depName, _ := parseGemDep(trimmed)
				if depName != "" {
					curGem.deps = append(curGem.deps, depName)
				}
			}

		case "DEPENDENCIES":
			// Direct dependencies: "  rails (~> 7.0)"
			depName, _ := parseGemDep(trimmed)
			if depName != "" {
				directs[depName] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gem: scanning %s: %w", gemfileLockName, err)
	}
	if len(gems) == 0 {
		return nil, fmt.Errorf("gem: %s contained no resolved gems", gemfileLockName)
	}

	// Build nodes.
	byName := map[string]string{} // name -> node ID
	for _, e := range gems {
		id := purl.NewGem(e.name, e.version).String()
		isDirect := directs[e.name]
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "gem", Name: e.name, Version: e.version,
			Direct: isDirect,
			Attr:   map[string]string{"gem.source": gemfileLockName},
		})
		n.SetSource(classifySection(e.section, e.remote))
		byName[e.name] = id
	}

	// Build edges.
	for _, e := range gems {
		fromID := byName[e.name]
		for _, dep := range e.deps {
			toID, ok := byName[dep]
			if !ok || toID == fromID {
				continue
			}
			g.AddEdge(fromID, toID, graph.EdgeDependsOn)
		}
		if directs[e.name] {
			g.AddEdge(root.ID, fromID, graph.EdgeDependsOn)
		}
	}

	// Any gem with no inbound edge from another gem hangs off root.
	hasInbound := map[string]bool{}
	for _, e := range g.SortedEdges() {
		if e.From != root.ID && e.Type == graph.EdgeDependsOn {
			hasInbound[e.To] = true
		}
	}
	for _, e := range gems {
		id := byName[e.name]
		if !hasInbound[id] && !directs[e.name] {
			g.AddEdge(root.ID, id, graph.EdgeDependsOn)
			if n := g.Get(id); n != nil {
				n.Direct = true
			}
		}
	}

	assignDepths(g, root.ID)
	return g, nil
}

// classifySection maps a Gemfile.lock section onto an ecosystem-neutral
// provenance class (Decision D-41). Bundler states this outright — a gem's
// section IS its origin — so no heuristics are needed.
func classifySection(section, remote string) (class, ref string) {
	switch section {
	case "GEM":
		return graph.SourceRegistry, remote
	case "GIT":
		return graph.SourceGit, remote
	case "PATH":
		return graph.SourcePath, remote
	}
	return "", ""
}

// parseGemSpec splits "name (version)" into name and version.
func parseGemSpec(s string) (string, string) {
	i := strings.LastIndexByte(s, '(')
	if i < 0 {
		return "", ""
	}
	name := strings.TrimSpace(s[:i])
	version := strings.TrimSpace(s[i+1:])
	version = strings.TrimSuffix(version, ")")
	version = strings.TrimSpace(version)
	return name, version
}

// parseGemDep splits "name (constraint)" or "name" into name.
func parseGemDep(s string) (string, string) {
	if i := strings.IndexByte(s, '('); i > 0 {
		return strings.TrimSpace(s[:i]), ""
	}
	if i := strings.IndexByte(s, '!'); i > 0 {
		return strings.TrimSpace(s[:i]), ""
	}
	return strings.TrimSpace(s), ""
}

func countIndent(line string) int {
	n := 0
	for _, ch := range line {
		if ch == ' ' {
			n++
		} else {
			break
		}
	}
	return n
}

func rootNode(g *graph.Graph, path string) *graph.Node {
	name := filepath.Base(strings.TrimSuffix(filepath.Clean(path), string(filepath.Separator)))
	if name == "." || name == "" || name == gemfileLockName {
		name = filepath.Base(filepath.Dir(path))
	}
	if name == "." || name == "" {
		name = "ruby-project"
	}
	id := purl.NewGem(name, "0.0.0").String()
	n := g.AddNode(&graph.Node{
		ID: id, Ecosystem: "gem", Name: name, Version: "0.0.0", Depth: 0,
	})
	g.MarkRoot(id)
	return n
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
	// Sort children for determinism.
	for k := range adj {
		sort.Strings(adj[k])
	}
}
