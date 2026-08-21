package npm

// pnpm-lock.yaml support (OPU-29, npm ecosystem).
//
// pnpm resolves the npm registry but writes a YAML lockfile, and the Go stdlib
// ships no YAML parser (D-10 forbids importing one). Unlike the TOML lockfiles
// this is genuinely nested YAML, so the reader is an INDENTATION-AWARE line
// scanner over the three sections pnpm v9 uses:
//
//   importers:  workspace projects and their direct deps + resolved versions
//   packages:   the resolved package universe (keyed 'name@version'), metadata
//   snapshots:  the dependency graph (keys may carry (peer@ver) suffixes)
//
// Package identity is the bare name@version (the `packages:` key). Snapshot keys
// and dependency values may carry peer suffixes like `(react@18.0.0)`; those are
// stripped to reconcile an edge target to its bare node. That collapses distinct
// peer-variants of one version onto a single node — a documented simplification,
// disclosed rather than silently precise.
//
// Versions are observed (pnpm resolved and pinned them). Supports lockfileVersion
// 9.x (the current split importers/packages/snapshots layout); an older/newer
// version is parsed best-effort and disclosed on the root.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

const pnpmLockName = "pnpm-lock.yaml"

func pnpmLockPath(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		p := filepath.Join(path, pnpmLockName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	if filepath.Base(path) == pnpmLockName {
		return path
	}
	return ""
}

type pnpmDirect struct {
	name    string
	version string
	section string // runtime | dev | optional
}

func parsePnpmLock(path string, raw []byte) (*graph.Graph, error) {
	lockVersion, universe, directs, edges := scanPnpmLock(raw)
	if len(universe) == 0 {
		return nil, fmt.Errorf("npm: %s contained no packages", pnpmLockName)
	}

	g := graph.New()

	// Nodes from the package universe (observed versions).
	nodeID := map[string]string{} // "name@version" -> PURL id
	for key := range universe {
		name, ver := splitPnpmKey(key)
		if name == "" || ver == "" {
			continue
		}
		id := purl.NewNpm(name, ver).String()
		nodeID[name+"@"+ver] = id
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "npm", Name: name, Version: ver,
			Attr: map[string]string{"npm.source": pnpmLockName},
		})
		n.SetSource(graph.SourceRegistry, "https://registry.npmjs.org")
	}

	// Synthesized project root (pnpm-lock records no root name/version).
	rootName := projectName(path)
	root := g.AddNode(&graph.Node{
		ID: purl.NewNpm(rootName, "0.0.0").String(), Ecosystem: "npm",
		Name: rootName, Version: "0.0.0",
		Attr: map[string]string{"npm.source": pnpmLockName, "npm.version_source": "synthesized"},
	})
	g.MarkRoot(root.ID)

	resolve := func(name, ver string) string {
		if id, ok := nodeID[name+"@"+stripPeer(ver)]; ok {
			return id
		}
		return ""
	}

	// Direct edges from importers.
	var rootUnresolved []string
	for _, d := range directs {
		id := resolve(d.name, d.version)
		if id == "" {
			rootUnresolved = append(rootUnresolved, d.name)
			continue
		}
		g.AddEdge(root.ID, id, graph.EdgeDependsOn)
		if n := g.Get(id); n != nil {
			n.Direct = true
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			if _, ok := n.Attr["npm.section"]; !ok {
				n.Attr["npm.section"] = d.section
			}
		}
	}

	// Transitive edges from snapshots.
	for from, deps := range edges {
		fn, fv := splitPnpmKey(from)
		fromID := resolve(fn, fv)
		if fromID == "" {
			continue
		}
		for _, dep := range deps {
			toID := resolve(dep.name, dep.version)
			if toID != "" {
				g.AddEdge(fromID, toID, graph.EdgeDependsOn)
			}
		}
	}

	if len(rootUnresolved) > 0 {
		if root.Attr == nil {
			root.Attr = map[string]string{}
		}
		root.Attr[graph.AttrUnresolved] = strings.Join(dedupeSorted(rootUnresolved), ",")
	}
	if lockVersion != "" && !strings.HasPrefix(lockVersion, "9") {
		root.Attr["npm.pnpmlock_format"] = lockVersion
	}

	attachUnrootedNpm(g, root.ID) // pull peer/optional-stranded components under root
	assignDepthsNpm(g, root.ID)
	return g, nil
}

// pnpmDep is one edge target read from a snapshot's dependency map.
type pnpmDep struct{ name, version string }

// scanPnpmLock walks the file once by indentation. Returns the lockfileVersion,
// the package universe (set of 'name@version' keys), the root's direct deps, and
// the snapshot edge map (snapshotKey -> its dependency list).
func scanPnpmLock(raw []byte) (lockVersion string, universe map[string]bool, directs []pnpmDirect, edges map[string][]pnpmDep) {
	universe = map[string]bool{}
	edges = map[string][]pnpmDep{}

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)

	section := "" // importers | packages | snapshots | ""(other/skip)
	curGroup := ""
	curDepName := ""
	curSnap := ""

	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		t := strings.TrimSpace(line)

		if indent == 0 {
			// top-level key
			switch {
			case strings.HasPrefix(t, "lockfileVersion:"):
				lockVersion = unquoteYAML(strings.TrimSpace(strings.TrimPrefix(t, "lockfileVersion:")))
				section = ""
			case t == "importers:":
				section = "importers"
			case t == "packages:":
				section = "packages"
			case t == "snapshots:":
				section = "snapshots"
			default:
				section = "" // settings:, overrides:, patchedDependencies:, ...
			}
			curGroup, curDepName, curSnap = "", "", ""
			continue
		}

		switch section {
		case "packages":
			if indent == 2 && strings.HasSuffix(t, ":") {
				universe[unquoteYAML(strings.TrimSuffix(t, ":"))] = true
			}
		case "snapshots":
			if indent == 2 && strings.HasSuffix(t, ":") || (indent == 2 && strings.Contains(t, ": {}")) {
				key := t
				key = strings.TrimSuffix(key, ": {}")
				key = strings.TrimSuffix(key, ":")
				curSnap = unquoteYAML(strings.TrimSpace(key))
				curGroup = ""
				if _, ok := edges[curSnap]; !ok {
					edges[curSnap] = nil
				}
			} else if indent == 4 && strings.HasSuffix(t, ":") {
				curGroup = strings.TrimSuffix(t, ":") // dependencies | optionalDependencies
			} else if indent == 6 && curSnap != "" {
				if name, ver, ok := splitYAMLPair(t); ok {
					edges[curSnap] = append(edges[curSnap], pnpmDep{name, stripPeer(ver)})
				}
			}
		case "importers":
			if indent == 2 {
				curGroup, curDepName = "", ""
			} else if indent == 4 && strings.HasSuffix(t, ":") {
				curGroup = strings.TrimSuffix(t, ":") // dependencies|devDependencies|optionalDependencies
				curDepName = ""
			} else if indent == 6 && strings.HasSuffix(t, ":") {
				curDepName = unquoteYAML(strings.TrimSuffix(t, ":"))
			} else if indent == 8 && strings.HasPrefix(t, "version:") && curDepName != "" {
				ver := stripPeer(unquoteYAML(strings.TrimSpace(strings.TrimPrefix(t, "version:"))))
				directs = append(directs, pnpmDirect{curDepName, ver, importerSection(curGroup)})
				curDepName = ""
			}
		}
	}
	return lockVersion, universe, directs, edges
}

func importerSection(group string) string {
	switch group {
	case "devDependencies":
		return "dev"
	case "optionalDependencies":
		return "optional"
	default:
		return "runtime"
	}
}

// splitPnpmKey turns a pnpm key ('@scope/name@1.2.3(peer@x)' or 'name@1.2.3')
// into (name, version). Peer suffixes are stripped; the version is the segment
// after the LAST '@' that is not the scope's leading '@'.
func splitPnpmKey(key string) (name, version string) {
	key = unquoteYAML(strings.TrimSpace(key))
	if i := strings.IndexByte(key, '('); i >= 0 { // strip peer suffix group(s)
		key = key[:i]
	}
	at := strings.LastIndexByte(key, '@')
	if at <= 0 { // no version, or bare scope
		return key, ""
	}
	return key[:at], key[at+1:]
}

// stripPeer removes a trailing pnpm peer suffix from a version string:
// "1.2.3(react@18.0.0)" -> "1.2.3".
func stripPeer(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		return strings.TrimSpace(v[:i])
	}
	return strings.TrimSpace(v)
}

// splitYAMLPair reads a `name: version` snapshot dependency line. The name may be
// quoted (scoped); the version runs to end of line.
func splitYAMLPair(t string) (name, version string, ok bool) {
	i := strings.Index(t, ": ")
	if i < 0 {
		return "", "", false
	}
	name = unquoteYAML(strings.TrimSpace(t[:i]))
	version = strings.TrimSpace(t[i+2:])
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func projectName(path string) string {
	dir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
	base := filepath.Base(strings.TrimRight(filepath.Clean(dir), string(filepath.Separator)))
	if base == "." || base == "" || base == string(filepath.Separator) {
		return "pnpm-project"
	}
	return base
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// small insertion sort keeps determinism without importing sort here
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// attachUnrootedNpm and assignDepthsNpm mirror the pypi helpers: guarantee every
// package node is reachable from the root (peer/optional stripping can strand a
// component) and assign real BFS depths.
func attachUnrootedNpm(g *graph.Graph, rootID string) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeDependsOn {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	reach := map[string]bool{rootID: true}
	bfs := func(s string) {
		q := []string{s}
		for len(q) > 0 {
			c := q[0]
			q = q[1:]
			for _, n := range adj[c] {
				if !reach[n] {
					reach[n] = true
					q = append(q, n)
				}
			}
		}
	}
	bfs(rootID)
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindPackage && n.ID != rootID && !reach[n.ID] {
			g.AddEdge(rootID, n.ID, graph.EdgeDependsOn)
			reach[n.ID] = true
			bfs(n.ID)
		}
	}
}

func assignDepthsNpm(g *graph.Graph, rootID string) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeDependsOn {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	depth := map[string]int{rootID: 0}
	seen := map[string]bool{rootID: true}
	q := []string{rootID}
	for len(q) > 0 {
		c := q[0]
		q = q[1:]
		for _, n := range adj[c] {
			if !seen[n] {
				seen[n] = true
				depth[n] = depth[c] + 1
				q = append(q, n)
			}
		}
	}
	for id, d := range depth {
		if n := g.Get(id); n != nil {
			n.Depth = d
		}
	}
}
