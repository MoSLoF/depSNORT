// Package pypi is the second ecosystem adapter. It exists to prove the
// ecosystem seam is real rather than decorative: the graph model, check
// contract, verdict engine, and every emitter are reused unchanged, and only
// parsing and name normalization differ.
//
// Supported inputs, both stdlib-parseable:
//
//   - requirements.txt — fully pinned (`name==version`). pip-compile output also
//     carries `# via <parent>` comments, which are the only place a
//     requirements file records WHICH package pulled in which; those are parsed
//     back into depends-on edges.
//   - Pipfile.lock — JSON, with `default` and `develop` sections.
//
// Poetry's poetry.lock and uv.lock are TOML. Go has no TOML parser in its
// standard library, and adding one would put a third-party dependency into a
// supply-chain-safety tool (Decision D-10). Those formats therefore wait for a
// minimal in-tree TOML subset reader rather than being bought with a dependency.
//
// Nothing here installs or executes anything (Decision D-04): pip is never run.
package pypi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
)

// Adapter implements ecosystem.Adapter for PyPI.
type Adapter struct {
	// Sdist fetches source distributions for install-surface analysis.
	// Nil means install-surface extraction is skipped (offline, or not configured).
	Sdist *SdistFetcher
}

// New returns a PyPI adapter without sdist fetching.
func New() *Adapter { return &Adapter{} }

// NewWithSdist returns a PyPI adapter with sdist fetching enabled for
// install-surface analysis.
func NewWithSdist(cache *datasource.Cache, offline bool) *Adapter {
	if offline {
		return &Adapter{}
	}
	return &Adapter{Sdist: NewSdistFetcher(cache, offline)}
}

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "pypi" }

const (
	requirementsName = "requirements.txt"
	pipfileLockName  = "Pipfile.lock"
)

// inputPath resolves a directory or file to a supported lockfile path and its
// kind, or ("", "").
func inputPath(path string) (file, kind string) {
	info, err := os.Stat(path)
	if err != nil {
		return "", ""
	}
	if info.IsDir() {
		// Pipfile.lock is a true lockfile; prefer it over requirements.txt.
		if p := filepath.Join(path, pipfileLockName); fileExists(p) {
			return p, "pipfile"
		}
		if p := filepath.Join(path, requirementsName); fileExists(p) {
			return p, "requirements"
		}
		return "", ""
	}
	switch filepath.Base(path) {
	case pipfileLockName:
		return path, "pipfile"
	case requirementsName:
		return path, "requirements"
	}
	return "", ""
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Detect implements ecosystem.Adapter.
func (*Adapter) Detect(path string) bool {
	f, _ := inputPath(path)
	return f != ""
}

// Resolve implements ecosystem.Adapter.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	file, kind := inputPath(path)
	if file == "" {
		return nil, fmt.Errorf("pypi: no %s or %s found at %q", requirementsName, pipfileLockName, path)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("pypi: reading %s: %w", file, err)
	}
	switch kind {
	case "pipfile":
		return parsePipfileLock(path, raw)
	default:
		return parseRequirements(path, raw)
	}
}

// rootNode creates the synthetic project root for a Python project, named after
// the containing directory (requirements files carry no project name).
func rootNode(g *graph.Graph, path string) *graph.Node {
	name := filepath.Base(strings.TrimSuffix(filepath.Clean(path), string(filepath.Separator)))
	if name == "." || name == "" || name == requirementsName || name == pipfileLockName {
		name = "python-project"
	}
	if strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".lock") {
		name = filepath.Base(filepath.Dir(path))
	}
	id := purl.NewPyPI(name, "0.0.0").String()
	n := g.AddNode(&graph.Node{
		ID: id, Ecosystem: "pypi", Name: purl.NormalizePyPI(name), Version: "0.0.0", Depth: 0,
		// "0.0.0" is always a placeholder here — nothing in this adapter reads a
		// real version out of setup.py/pyproject.toml (consistent with the
		// zero-execution ethos: a setuptools_scm/hatch-vcs project computes its
		// real version by running git, which this tool will never do). Tagged
		// so a reader can tell "genuinely 0.0.0" apart from "could not
		// determine" without already knowing the project.
		Attr: map[string]string{"pypi.version_source": "unresolved-placeholder"},
	})
	g.MarkRoot(id)
	return n
}

// ---- requirements.txt ----------------------------------------------------

// unparseableToken renders an unreadable requirements.txt line as one
// disclosure token for graph.AttrUnresolved.
//
// Two constraints on the shape, both load-bearing: AttrUnresolved is
// comma-joined at the root and re-split by internal/graph/coverage.go with no
// escaping, so the token must be comma-free; and the line scanner permits a
// 4 MB line, so it must be length-bounded before it reaches a graph attribute.
// Truncation is rune-aware so a multi-byte character is never cut in half.
func unparseableToken(line string) string {
	const max = 60
	t := strings.TrimSpace(line)
	t = strings.ReplaceAll(t, ",", " ")
	if r := []rune(t); len(r) > max {
		t = string(r[:max]) + "…"
	}
	return "<unparseable: " + t + ">"
}

// parseRequirements reads a fully pinned requirements file. Only `==` pins are
// treated as resolved; a loose specifier (>=, ~=, unpinned) is NOT resolved,
// because guessing which version a range would install is exactly the resolver
// reimplementation D-01 rules out. Unpinned lines are counted and reported.
func parseRequirements(path string, raw []byte) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, path)

	type entry struct {
		name    string
		version string
		vias    []string
		marker  string
	}
	var entries []entry
	var unpinned []string
	var markerExcluded []string
	// hasProvenance is true the moment any line contributes a `# via` parent.
	// A file with zero provenance (plain `pip freeze` output) resolves every
	// entry as a direct root dependency by construction, not by fact — the
	// same "format cannot express structure" situation Pipfile.lock records
	// via AttrFlatResolution.
	hasProvenance := false

	// Strip a leading UTF-8 BOM: `pip freeze > requirements.txt` under Windows
	// PowerShell 5.1 (and any Notepad save) emits one, and strings.TrimSpace
	// does not remove U+FEFF — it is category Cf, not White_Space — so the
	// first dependency in the file would otherwise fail to parse.
	sc := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(raw), "\uFEFF")))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var cur *entry
	inVia := false
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// pip-compile provenance comments:
		//   # via
		//   #   -r requirements.in
		//   #   some-parent
		if strings.HasPrefix(trimmed, "#") {
			comment := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			switch {
			case comment == "via":
				inVia = true
			case strings.HasPrefix(comment, "via "):
				if cur != nil {
					if v := viaTarget(strings.TrimPrefix(comment, "via ")); v != "" {
						cur.vias = append(cur.vias, v)
						hasProvenance = true
					}
				}
				inVia = false
			case inVia && cur != nil:
				if v := viaTarget(comment); v != "" {
					cur.vias = append(cur.vias, v)
					hasProvenance = true
				}
			}
			continue
		}
		inVia = false

		// Skip pip flags and includes.
		if strings.HasPrefix(trimmed, "-") {
			continue
		}
		// Strip inline hashes / continuations and trailing comments.
		body := trimmed
		if i := strings.Index(body, " --hash"); i >= 0 {
			body = body[:i]
		}
		body = strings.TrimSuffix(strings.TrimSpace(body), "\\")
		if i := strings.Index(body, " #"); i >= 0 {
			body = body[:i]
		}
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}

		name, version, pinned, marker := pep508.Split(body)
		if name == "" {
			// pep508.Split could not read this line as a requirement at all — a
			// bare URL or local path, a name violating PEP 508's grammar, a
			// stray fragment. That is a coverage gap, not an absent dependency,
			// so it is DISCLOSED rather than silently dropped (D-24). Folding it
			// into `unpinned` reuses the existing AttrUnresolved channel, so it
			// degrades coverage exactly like any other unresolved requirement.
			unpinned = append(unpinned, unparseableToken(body))
			continue
		}
		if !pinned {
			if marker != "" && pep508.ExcludesLinux(marker) {
				markerExcluded = append(markerExcluded, name)
			} else {
				unpinned = append(unpinned, name)
			}
			continue
		}
		entries = append(entries, entry{name: name, version: version, marker: marker})
		cur = &entries[len(entries)-1]
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("pypi: scanning %s: %w", requirementsName, err)
	}
	if len(entries) == 0 && len(unpinned) == 0 {
		return nil, fmt.Errorf("pypi: %s contained no requirements", requirementsName)
	}

	// Nodes.
	byName := map[string]string{} // normalized name -> node ID
	for _, e := range entries {
		id := purl.NewPyPI(e.name, e.version).String()
		attr := map[string]string{"pypi.source": requirementsName}
		if e.marker != "" {
			attr["pypi.marker"] = e.marker
		}
		g.AddNode(&graph.Node{
			ID: id, Ecosystem: "pypi", Name: purl.NormalizePyPI(e.name), Version: e.version,
			Attr: attr,
		})
		byName[purl.NormalizePyPI(e.name)] = id
	}

	// Edges from `# via` provenance; anything sourced from a -r/-c include or an
	// unknown parent hangs off the root as a direct dependency.
	for _, e := range entries {
		id := byName[purl.NormalizePyPI(e.name)]
		linked := false
		for _, v := range e.vias {
			parent, ok := byName[purl.NormalizePyPI(v)]
			if !ok || parent == id {
				continue
			}
			g.AddEdge(parent, id, graph.EdgeDependsOn)
			linked = true
		}
		if !linked {
			g.AddEdge(root.ID, id, graph.EdgeDependsOn)
			if n := g.Get(id); n != nil {
				n.Direct = true
			}
		}
	}

	// Root-level facts are written into the existing root.Attr map (rootNode
	// always populates it) rather than replaced wholesale — several conditions
	// below can all be true for the same file (e.g. partially unpinned AND
	// fully flat), and a bare `root.Attr = map[string]string{...}` would drop
	// whichever fact was written first, including rootNode's own attributes.
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	if len(unpinned) > 0 {
		sort.Strings(unpinned)
		// Surfaced as a graph fact so degraded coverage is visible rather than
		// silently reported as a clean, fully-resolved tree.
		root.Attr[graph.AttrUnresolved] = strings.Join(unpinned, ",")
		root.Attr[graph.AttrUnresolvedCount] = fmt.Sprintf("%d", len(unpinned))
	}
	if len(markerExcluded) > 0 {
		sort.Strings(markerExcluded)
		// Not folded into AttrUnresolved: these are deliberately excluded from
		// the coverage gate because their marker proves they never install on
		// this platform. The exclusion itself is still disclosed, not silent.
		root.Attr["pypi.marker_excluded"] = strings.Join(markerExcluded, ",")
	}
	if !hasProvenance && len(entries) > 0 {
		// No line in the file contributed a `# via` parent at all — the same
		// "format records no inter-package relationships" situation
		// Pipfile.lock is in, just for a plain `pip freeze` requirements.txt
		// instead of a lockfile format.
		root.Attr[graph.AttrFlatResolution] = "pypi"
	}

	assignDepths(g, root.ID)
	return g, nil
}

// viaTarget extracts a parent package name from a pip-compile `via` line,
// ignoring file references like "-r requirements.in".
func viaTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") {
		return ""
	}
	// "some-parent (setup.py)" -> "some-parent"
	if i := strings.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	return s
}

// ---- Pipfile.lock --------------------------------------------------------

type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string   `json:"version"` // e.g. "==2.31.0"
	Hashes  []string `json:"hashes"`
}

// parsePipfileLock reads a Pipfile.lock. It records no edges: the format lists
// a flat resolved set without provenance, so every entry hangs off the root.
// That is a real limitation of the format, recorded rather than invented.
func parsePipfileLock(path string, raw []byte) (*graph.Graph, error) {
	var lf pipfileLock
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("pypi: parsing %s: %w", pipfileLockName, err)
	}
	g := graph.New()
	root := rootNode(g, path)

	add := func(section string, m map[string]pipfileEntry) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names) // determinism (D-13)
		for _, name := range names {
			version := strings.TrimPrefix(strings.TrimSpace(m[name].Version), "==")
			if version == "" {
				continue
			}
			id := purl.NewPyPI(name, version).String()
			g.AddNode(&graph.Node{
				ID: id, Ecosystem: "pypi", Name: purl.NormalizePyPI(name), Version: version,
				Direct: true, Depth: 1,
				Attr: map[string]string{"pypi.source": pipfileLockName, "pypi.section": section},
			})
			g.AddEdge(root.ID, id, graph.EdgeDependsOn)
		}
	}
	add("default", lf.Default)
	add("develop", lf.Develop)

	if g.Len() == 1 {
		return nil, fmt.Errorf("pypi: %s contained no resolved packages", pipfileLockName)
	}

	// Record the format's limitation as a coverage fact (Decision D-24). Every
	// package here sits at depth 1 because Pipfile.lock does not express
	// inter-package relationships — not because the tree is genuinely one layer
	// deep. Without this the depth histogram silently implies the opposite.
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr[graph.AttrFlatResolution] = "pypi"

	assignDepths(g, root.ID)
	return g, nil
}

// ---- shared --------------------------------------------------------------

// assignDepths does a BFS from root, setting each node's shortest depth.
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
}
