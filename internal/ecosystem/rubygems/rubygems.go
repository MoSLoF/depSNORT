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

const (
	gemfileLockName = "Gemfile.lock"
	gemfileName     = "Gemfile"
)

// Detect implements ecosystem.Adapter. A Gemfile.lock (a resolved tree) claims
// the project; failing that, a Gemfile declaring at least one gem claims it as a
// manifest-only project — the same lock-or-manifest handling npm, PyPI, and
// Composer already have (OPU-11). Without this, a gem library or any project
// committed without a lock (the common convention, where Gemfile.lock is
// git-ignored) read as "nothing to scan" (OPU-16).
func (*Adapter) Detect(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return fileExists(filepath.Join(path, gemfileLockName)) ||
			gemfileDeclaresGems(filepath.Join(path, gemfileName))
	}
	base := filepath.Base(path)
	return base == gemfileLockName || (base == gemfileName && gemfileDeclaresGems(path))
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Resolve implements ecosystem.Adapter. Gemfile.lock takes precedence (observed
// versions beat presumed); with no lock, a Gemfile is parsed manifest-only and
// its declared gems ride to the expansion tier (D-44), exactly as a lock-less
// package.json, pyproject.toml, or composer.json is handled.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("gem: %w", err)
	}
	if !info.IsDir() {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("gem: reading %s: %w", filepath.Base(path), err)
		}
		if filepath.Base(path) == gemfileName {
			return parseGemfile(path, raw)
		}
		return parseGemfileLock(path, raw)
	}
	if lock := filepath.Join(path, gemfileLockName); fileExists(lock) {
		raw, err := os.ReadFile(lock)
		if err != nil {
			return nil, fmt.Errorf("gem: reading %s: %w", gemfileLockName, err)
		}
		return parseGemfileLock(path, raw)
	}
	gemfile := filepath.Join(path, gemfileName)
	raw, err := os.ReadFile(gemfile)
	if err != nil {
		return nil, fmt.Errorf("gem: reading %s: %w", gemfileName, err)
	}
	return parseGemfile(path, raw)
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

// gemfileDeclaresGems reports whether a Gemfile at p declares at least one gem —
// the gate for claiming a lock-less Ruby project.
func gemfileDeclaresGems(p string) bool {
	raw, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		if name, _, ok := parseGemLine(sc.Text()); ok && name != "" {
			return true
		}
	}
	return false
}

// parseGemfile builds a manifest-only graph from a Gemfile with no lockfile: the
// project root plus its declared (name + constraint) gems, which the expansion
// tier presumes or asserts a version for (D-44). The Gemfile is a Ruby DSL, not a
// resolved list, so only `gem 'name'[, 'constraint'...]` declarations are read;
// `source`, `ruby`, `group`, `gemspec`, and comments are skipped. Mirrors
// composer/parseComposerManifest and pypi/parsePyproject.
func parseGemfile(path string, raw []byte) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, path)

	var declared []graph.DeclaredDep
	var names []string
	seen := map[string]bool{}

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		name, constraint, ok := parseGemLine(sc.Text())
		if !ok || name == "" {
			continue
		}
		// Gem names are case-sensitive and carry no scope (WalkSource.Identify
		// uses them verbatim), so nothing is folded — the OPU-14 case-discipline
		// lesson: fold only where the registry/OSV coordinate is case-insensitive.
		if seen[name] {
			continue
		}
		seen[name] = true
		declared = append(declared, graph.DeclaredDep{Name: name, Constraint: constraint})
		names = append(names, name)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("gem: scanning %s: %w", gemfileName, err)
	}
	if len(declared) == 0 {
		return nil, fmt.Errorf("gem: %s declares no gems", gemfileName)
	}
	sort.Slice(declared, func(i, j int) bool { return declared[i].Name < declared[j].Name })
	sort.Strings(names)

	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["gem.source"] = gemfileName
	root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(declared)
	// Surfaced as a coverage fact so a manifest-only project degrades coverage
	// (its versions are presumed, not observed) rather than reading as a clean,
	// fully-resolved tree — the same disclosure npm/PyPI/Composer make.
	root.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
	root.Attr[graph.AttrUnresolvedCount] = fmt.Sprintf("%d", len(names))
	root.Attr[graph.AttrFlatResolution] = "gem"
	return g, nil
}

// parseGemLine reads one Gemfile line as a `gem` declaration. It returns the gem
// name and a comma-joined version constraint (RubyGems AND semantics, which
// SatisfiesRuby understands), or ok=false for any non-`gem` line (source, ruby,
// group, gemspec, comments, blanks). Tolerant and line-based, like the Poetry
// constraint reader: positional quoted arguments are the name and its version
// constraints; the first `key:`/`:symbol` option (require:, git:, group:, …)
// ends the positional run, so a git/path/github source is ignored and the gem is
// still scanned by name.
func parseGemLine(line string) (name, constraint string, ok bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", "", false
	}
	// The keyword must be exactly `gem`, followed by whitespace or a quote — not
	// `gemspec`, `gem_name`, or `git_source`.
	if !strings.HasPrefix(t, "gem") {
		return "", "", false
	}
	rest := t[len("gem"):]
	if rest == "" {
		return "", "", false
	}
	switch rest[0] {
	case ' ', '\t', '\'', '"', '(':
	default:
		return "", "", false
	}
	rest = strings.TrimLeft(rest, " \t(")

	var constraints []string
	for _, seg := range strings.Split(rest, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if seg[0] != '\'' && seg[0] != '"' {
			// An option (require: false, git: '…', :symbol) — positional args end.
			break
		}
		val, valOK := firstQuoted(seg)
		if !valOK {
			break
		}
		if name == "" {
			name = val
		} else {
			constraints = append(constraints, val)
		}
	}
	if name == "" {
		return "", "", false
	}
	return name, strings.Join(constraints, ", "), true
}

// firstQuoted returns the contents of the first single- or double-quoted string
// in s, ignoring anything after it (a trailing comment or option).
func firstQuoted(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	q := s[0]
	if q != '\'' && q != '"' {
		return "", false
	}
	if i := strings.IndexByte(s[1:], q); i >= 0 {
		return s[1 : 1+i], true
	}
	return "", false
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
