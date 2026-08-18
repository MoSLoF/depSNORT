// Package npm is the first ecosystem adapter: it statically resolves an npm
// project's dependency tree from package-lock.json.
//
// It supports lockfileVersion 2 and 3 (the "packages" map keyed by
// node_modules paths) and falls back to lockfileVersion 1 (nested
// "dependencies"). Resolution mirrors npm's hoisting rule: a dependency is
// resolved to the nearest node_modules entry walking up the path, then the
// root. No install is performed and no hook is executed (Decision D-04).
package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// Adapter implements ecosystem.Adapter for npm.
type Adapter struct{}

// New returns an npm adapter.
func New() *Adapter { return &Adapter{} }

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "npm" }

const lockName = "package-lock.json"

// lockPath resolves path (a dir or a file) to a package-lock.json path if one
// applies, else "".
func lockPath(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		p := filepath.Join(path, lockName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	if filepath.Base(path) == lockName {
		return path
	}
	return ""
}

// Detect implements ecosystem.Adapter.
func (*Adapter) Detect(path string) bool { return lockPath(path) != "" }

// lockfile is the subset of package-lock.json we parse.
type lockfile struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	LockfileVersion int    `json:"lockfileVersion"`
	// v2/v3: keyed by "" (root) and "node_modules/..." paths.
	Packages map[string]lockPackage `json:"packages"`
	// v1: nested tree.
	Dependencies map[string]lockDepV1 `json:"dependencies"`
}

type lockPackage struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Resolved        string            `json:"resolved"` // registry URL the version came from
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	OptionalDeps    map[string]string `json:"optionalDependencies"`
	// PeerDependencies are auto-installed by npm 7+, so they are real edges.
	// Without them a peer sits in the lockfile with no inbound edge: `konva` is
	// a peer of `react-konva`, and both were stranded in a real workspace scan.
	PeerDependencies map[string]string `json:"peerDependencies"`
	// HasInstallScript is npm's own flag that the package declares an install
	// lifecycle hook. It is a FACT surfaced by the adapter; judging it is the
	// job of the VC-002 family (step 5), not this parser.
	HasInstallScript bool `json:"hasInstallScript"`
	// Dev marks a package present only for development. Recorded as a fact so a
	// consumer can weight or filter dev-only exposure differently from runtime.
	Dev bool `json:"dev"`
}

type lockDepV1 struct {
	Version      string               `json:"version"`
	Dev          bool                 `json:"dev"`
	Requires     map[string]string    `json:"requires"`
	Dependencies map[string]lockDepV1 `json:"dependencies"`
}

// Resolve implements ecosystem.Adapter.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	lp := lockPath(path)
	if lp == "" {
		return nil, fmt.Errorf("npm: no %s found at %q", lockName, path)
	}
	raw, err := os.ReadFile(lp)
	if err != nil {
		return nil, fmt.Errorf("npm: reading lockfile: %w", err)
	}
	return parseLock(raw)
}

// parseLock turns package-lock.json bytes into a graph. Split out from Resolve
// so parsing is reachable without touching the filesystem — which is what the
// fuzz target drives (D-33), and mirrors the parseX(path, raw) seam the other
// five adapters already expose.
func parseLock(raw []byte) (*graph.Graph, error) {
	var lf lockfile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("npm: parsing %s: %w", lockName, err)
	}

	g := graph.New()
	switch {
	case len(lf.Packages) > 0:
		resolveV2(g, &lf)
	case len(lf.Dependencies) > 0:
		resolveV1(g, &lf)
	default:
		// A lockfile with neither section is a project with NO dependencies —
		// which is a legitimate, and perfectly clean, thing to scan. Treating it
		// as a parse error made a real workspace report a resolve failure for a
		// dependency-free project, understating coverage for no reason. Emit the
		// root node alone so the project is counted and reported as clean.
		rootName := firstNonEmpty(lf.Name, "root")
		rootVer := firstNonEmpty(lf.Version, "0.0.0")
		rootID := purl.NewNpm(rootName, rootVer).String()
		g.AddNode(&graph.Node{
			ID: rootID, Ecosystem: "npm", Name: rootName, Version: rootVer, Depth: 0,
			Attr: map[string]string{"npm.path": "."},
		})
		g.MarkRoot(rootID)
	}
	return g, nil
}

// ---- lockfileVersion 2/3 -------------------------------------------------

func resolveV2(g *graph.Graph, lf *lockfile) {
	// Root project node.
	rootPkg := lf.Packages[""]
	rootName := firstNonEmpty(rootPkg.Name, lf.Name, "root")
	rootVer := firstNonEmpty(rootPkg.Version, lf.Version, "0.0.0")
	rootID := purl.NewNpm(rootName, rootVer).String()
	root := g.AddNode(&graph.Node{
		ID: rootID, Ecosystem: "npm", Name: rootName, Version: rootVer, Direct: false, Depth: 0,
		Attr: map[string]string{"npm.path": "."},
	})
	g.MarkRoot(root.ID)

	directNames := mergeKeys(rootPkg.Dependencies, rootPkg.DevDependencies, rootPkg.OptionalDeps)

	// Create a node for every packages[] entry (skip root "").
	// Iterate SORTED keys: ranging a map directly gives Go's randomized order,
	// which leaks into edge insertion order and breaks scan determinism (D-09).
	for _, key := range sortedKeys(lf.Packages) {
		pkg := lf.Packages[key]
		if key == "" {
			continue
		}
		name := pkgNameFromKey(key, pkg.Name)
		if name == "" || pkg.Version == "" {
			continue
		}
		id := npmNodeID(name, pkg)
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "npm", Name: name, Version: pkg.Version,
			Direct: directNames[name],
		})
		if pkg.HasInstallScript {
			// Record the FACT; do not judge it here.
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			n.Attr["npm.hasInstallScript"] = "true"
		}
		if pkg.Resolved != "" {
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			n.Attr["npm.resolved"] = pkg.Resolved
			class, ref := classifyResolved(pkg.Resolved)
			n.SetSource(class, ref)
		}
		if pkg.Dev {
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			n.Attr["npm.dev"] = "true"
		}
		// Record where this package lives in the tree so install-surface
		// extraction can locate its package.json without re-parsing the lock.
		if n.Attr == nil {
			n.Attr = map[string]string{}
		}
		if _, exists := n.Attr["npm.path"]; !exists {
			n.Attr["npm.path"] = key
		}
	}

	// Edges: for each entry, resolve each dependency by npm hoisting.
	for _, key := range sortedKeys(lf.Packages) {
		pkg := lf.Packages[key]
		fromName := pkgNameFromKey(key, pkg.Name)
		fromVer := pkg.Version
		if key == "" {
			fromName, fromVer = rootName, rootVer
		}
		if fromName == "" || fromVer == "" {
			continue
		}
		fromID := purl.NewNpm(fromName, fromVer).WithSource(classifyResolved(pkg.Resolved)).String()
		if key == "" {
			fromID = rootID // the root keeps its bare coordinate
		}
		// npm installs the ROOT project's devDependencies, but not those of any
		// dependency — a package's own devDeps are never installed downstream.
		// So devDeps produce edges for the root entry only.
		//
		// Omitting them entirely (the original behaviour) left every devDep with
		// a node but no inbound edge, which stranded its whole transitive subtree
		// as unreachable: on a real 59-repo workspace that was 2,687 of 5,371
		// packages sitting at depth 0, disconnected from any root.
		deps := mergeKeys(pkg.Dependencies, pkg.OptionalDeps, pkg.PeerDependencies)
		if key == "" {
			deps = mergeKeys(pkg.Dependencies, pkg.OptionalDeps, pkg.PeerDependencies, pkg.DevDependencies)
		}
		for _, dep := range sortedSet(deps) {
			if depPath, ok := resolveHoisted(lf.Packages, key, dep); ok {
				dp := lf.Packages[depPath]
				toName := pkgNameFromKey(depPath, dp.Name)
				toID := npmNodeID(toName, dp)
				g.AddEdge(fromID, toID, graph.EdgeDependsOn)
			}
		}
	}
	assignDepths(g, rootID)
}

// resolveHoisted finds the packages[] key that satisfies dependency dep for the
// package located at fromKey, following npm's nearest-node_modules-then-up rule.
func resolveHoisted(pkgs map[string]lockPackage, fromKey, dep string) (string, bool) {
	prefix := fromKey
	if prefix != "" {
		prefix += "/"
	}
	// Try the requester's own node_modules first, then walk up.
	candidate := prefix + "node_modules/" + dep
	for {
		if _, ok := pkgs[candidate]; ok {
			return candidate, true
		}
		// Strip one "node_modules/<pkg>" level and retry higher up.
		idx := strings.LastIndex(candidate, "node_modules/")
		if idx <= 0 {
			break
		}
		// Move to the parent scope: everything before this node_modules segment,
		// minus the trailing "<pkg>/" that owned it.
		parent := candidate[:idx]
		parent = strings.TrimSuffix(parent, "/")
		// Drop the owning package path segment to climb to its container.
		if j := strings.LastIndex(parent, "node_modules/"); j >= 0 {
			parent = parent[:j]
		} else {
			parent = ""
		}
		candidate = strings.TrimSuffix(parent, "/")
		if candidate != "" {
			candidate += "/"
		}
		candidate += "node_modules/" + dep
		if idx == 0 {
			break
		}
	}
	// Final fallback: top-level.
	top := "node_modules/" + dep
	if _, ok := pkgs[top]; ok {
		return top, true
	}
	return "", false
}

// pkgNameFromKey derives the package name from a packages[] key like
// "node_modules/@scope/pkg" or "a/node_modules/b", preferring an explicit name.
func pkgNameFromKey(key, explicit string) string {
	if explicit != "" {
		return explicit
	}
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return ""
	}
	return key[idx+len("node_modules/"):]
}

// ---- lockfileVersion 1 ---------------------------------------------------

func resolveV1(g *graph.Graph, lf *lockfile) {
	rootName := firstNonEmpty(lf.Name, "root")
	rootVer := firstNonEmpty(lf.Version, "0.0.0")
	rootID := purl.NewNpm(rootName, rootVer).String()
	g.AddNode(&graph.Node{
		ID: rootID, Ecosystem: "npm", Name: rootName, Version: rootVer, Depth: 0,
		Attr: map[string]string{"npm.path": "."},
	})
	g.MarkRoot(rootID)

	type v1Entry struct {
		id       string
		requires map[string]string
		path     []string
	}
	var entries []v1Entry

	var walk func(parentID string, deps map[string]lockDepV1, direct bool, path []string)
	walk = func(parentID string, deps map[string]lockDepV1, direct bool, path []string) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			d := deps[name]
			if d.Version == "" {
				continue
			}
			id := purl.NewNpm(name, d.Version).String()
			g.AddNode(&graph.Node{ID: id, Ecosystem: "npm", Name: name, Version: d.Version, Direct: direct})
			g.AddEdge(parentID, id, graph.EdgeDependsOn)
			entryPath := make([]string, len(path)+1)
			copy(entryPath, path)
			entryPath[len(path)] = name
			if len(d.Requires) > 0 {
				entries = append(entries, v1Entry{id: id, requires: d.Requires, path: entryPath})
			}
			if len(d.Dependencies) > 0 {
				walk(id, d.Dependencies, false, entryPath)
			}
		}
	}
	walk(rootID, lf.Dependencies, true, nil)

	// Second pass: create edges for requires entries. In v1 lockfiles,
	// requires records which packages a dependency needs. When those
	// packages are hoisted (not nested under the consumer), the walk
	// misses the edge. Resolve each by walking up the nesting tree.
	for _, e := range entries {
		reqNames := make([]string, 0, len(e.requires))
		for n := range e.requires {
			reqNames = append(reqNames, n)
		}
		sort.Strings(reqNames)
		for _, reqName := range reqNames {
			ver := resolveV1Require(lf.Dependencies, e.path, reqName)
			if ver != "" {
				g.AddEdge(e.id, purl.NewNpm(reqName, ver).String(), graph.EdgeDependsOn)
			}
		}
	}

	assignDepths(g, rootID)
}

// resolveV1Require walks up the v1 nesting tree from path to find the
// package named name, matching npm's resolution algorithm.
func resolveV1Require(rootDeps map[string]lockDepV1, path []string, name string) string {
	for i := len(path); i >= 0; i-- {
		deps := v1DepsAt(rootDeps, path[:i])
		if deps == nil {
			continue
		}
		if entry, ok := deps[name]; ok && entry.Version != "" {
			return entry.Version
		}
	}
	return ""
}

// v1DepsAt navigates into the v1 nesting tree and returns the dependencies
// map at the given path. An empty path returns the root-level deps.
func v1DepsAt(rootDeps map[string]lockDepV1, path []string) map[string]lockDepV1 {
	deps := rootDeps
	for _, seg := range path {
		entry, ok := deps[seg]
		if !ok {
			return nil
		}
		deps = entry.Dependencies
		if deps == nil {
			return nil
		}
	}
	return deps
}

// ---- helpers -------------------------------------------------------------

// assignDepths does a BFS from root to set each node's shortest depth.
func assignDepths(g *graph.Graph, rootID string) {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeDependsOn {
			adj[e.From] = append(adj[e.From], e.To)
		}
	}
	seen := map[string]bool{rootID: true}
	queue := []string{rootID}
	depth := map[string]int{rootID: 0}
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

// sortedKeys returns a lockfile's package keys in stable order.
func sortedKeys(m map[string]lockPackage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedSet returns a set's members in stable order.
func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mergeKeys(maps ...map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, m := range maps {
		for k := range m {
			out[k] = true
		}
	}
	return out
}

// npmNodeID builds the node identity for one lockfile entry, carrying the
// package's origin when that origin is not a registry (D-42).
//
// npm can hold the same name@version twice in one tree — a registry copy
// hoisted at the top and a git fork nested under a dependency that pinned it.
// They shared a PURL before this, so the graph kept one node and the entry
// parsed second overwrote its provenance: a registry package could report as
// git-sourced, or a fork could be masked as registry and slip past VC-009.
// The lockfile distinguishes them in `resolved`; now the identity does too.
func npmNodeID(name string, pkg lockPackage) string {
	return purl.NewNpm(name, pkg.Version).WithSource(classifyResolved(pkg.Resolved)).String()
}

// classifyResolved maps a package-lock `resolved` value onto an
// ecosystem-neutral provenance class (Decision D-41).
//
// npm's shapes that matter are the non-HTTP ones. A `git+https://…` or
// `github:owner/repo#ref` dependency is code npm clones and builds — commonly
// WITH lifecycle scripts, and pinned to a ref an upstream force-push can
// replace. A `file:`/`link:` dependency is local source that was never
// published anywhere.
//
// An https URL is treated as a registry coordinate whether or not the host is
// npmjs.org, because a private or mirrored registry is still a registry: the
// package has a name@version an advisory feed can be asked about, which is the
// only property this classification is about. Flagging every enterprise
// Artifactory URL as unverifiable would be exactly the warning tax that gets a
// detector muted, and it would say something false besides.
func classifyResolved(resolved string) (class, ref string) {
	r := strings.TrimSpace(resolved)
	if r == "" {
		return "", ""
	}
	switch c := graph.ClassifyRef(r); c {
	case graph.SourceGit, graph.SourcePath:
		return c, r
	}
	if strings.HasPrefix(strings.ToLower(r), "http://") ||
		strings.HasPrefix(strings.ToLower(r), "https://") {
		return graph.SourceRegistry, r
	}
	return graph.SourceUnknown, r
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
