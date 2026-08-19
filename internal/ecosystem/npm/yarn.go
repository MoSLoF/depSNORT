package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// yarn.lock support.
//
// yarn.lock is a FLAT, descriptor-keyed resolution — unlike package-lock.json it
// carries no root node and no node_modules tree. The project root and its direct
// dependencies live in the sibling package.json; yarn.lock maps each requested
// "name@range" descriptor to the concrete version yarn selected, plus that
// version's own dependency descriptors. This path joins the two: package.json
// names the root and its direct deps, yarn.lock resolves every descriptor to a
// version and supplies the transitive edges. Kibana's real dependency graph
// lives here, and before this it was invisible — the whole application tree read
// as "no supported lockfile" (live-fire round 2).
//
// Both dialects are read by one parser. Yarn v1 ("classic") is a bespoke
// indentation format; Yarn v2+ ("berry") is YAML. They differ only in
// punctuation — v1 quotes each descriptor and separates key from value with a
// space; berry joins descriptors in a single quoted string, uses YAML colons,
// and prefixes ranges with "npm:". The block structure is identical, so
// normalizing the range (dropping a leading "npm:") lets one set of descriptors
// match across both.
//
// What yarn.lock does NOT record, and this path therefore does not claim: an
// install-script flag (package-lock's hasInstallScript), a dev/prod marking per
// package, or an on-disk node_modules path. Install-surface extraction keys on
// that path, so a yarn tree contributes no npm.path and surfaces as
// source-unavailable rather than a fabricated location — honest under D-24.

const yarnLockName = "yarn.lock"

// yarnLockPath resolves a dir or file to a yarn.lock path, else "".
func yarnLockPath(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		p := filepath.Join(path, yarnLockName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	if filepath.Base(path) == yarnLockName {
		return path
	}
	return ""
}

// yarnEntry is one resolved block: the descriptors that resolve to it, the
// concrete version yarn chose, its origin, and its own dependency descriptors.
type yarnEntry struct {
	descriptors []string
	version     string
	resolved    string
	deps        map[string]string // dep name -> raw range (the descriptor tail)
}

// resolveYarn reads a yarn.lock (and its sibling package.json, if present) into a
// graph. dir is the directory holding the lockfile, used to name a root that the
// manifest does not.
func resolveYarn(lockPath string) (*graph.Graph, error) {
	lockRaw, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(lockPath)
	manifestRaw, _ := os.ReadFile(filepath.Join(dir, manifestName)) // absent is fine
	return parseYarnLock(lockRaw, manifestRaw, dir)
}

// parseYarnLock is the filesystem-free core, so the fuzz target and tests reach
// it directly — the parseX(raw) seam the other adapters expose.
func parseYarnLock(lockRaw, manifestRaw []byte, dir string) (*graph.Graph, error) {
	entries := scanYarnLock(lockRaw)

	// Drop non-package blocks so they never materialize as nodes: Berry's
	// `__metadata:` header, and a workspace/portal/link SELF-entry (the project
	// or a workspace member describing itself, e.g. "app@workspace:."). The real
	// root is built from package.json by yarnAttachRoot; a workspace self-entry
	// would otherwise become a phantom `0.0.0-use.local` duplicate of it, and
	// `__metadata` a phantom package named "__metadata" (OPU-07).
	pkgs := entries[:0]
	for _, e := range entries {
		if !isNonPackageYarnEntry(e) {
			pkgs = append(pkgs, e)
		}
	}
	entries = pkgs

	g := graph.New()

	// descNode maps a normalized "name@range" descriptor to its resolved node ID,
	// so a dependency reference resolves to the exact node yarn chose. byName is
	// the single-version fallback: when a descriptor string does not match (yarn
	// rewrote a range, or a manifest range differs), a name with exactly one
	// resolved version is still unambiguous.
	descNode := map[string]string{}
	byName := map[string][]string{}
	for _, e := range entries {
		if e.version == "" || len(e.descriptors) == 0 {
			continue
		}
		// The node's SECURITY IDENTITY is the real package, unwrapping a yarn
		// alias (alias@npm:REALNAME@range) to REALNAME — otherwise the node is
		// named for the local alias, OSV/registry/typosquat are queried by the
		// alias, and a malicious impostor published under the bare alias name is
		// matched against the innocent aliased package (OPU-08).
		name := yarnResolvedName(e.descriptors[0])
		if name == "" {
			continue
		}
		id := purl.NewNpm(name, e.version).WithSource(classifyResolved(e.resolved)).String()
		if g.Get(id) == nil {
			n := g.AddNode(&graph.Node{ID: id, Ecosystem: "npm", Name: name, Version: e.version})
			if e.resolved != "" {
				n.Attr = map[string]string{"npm.resolved": e.resolved}
				n.SetSource(classifyResolved(e.resolved))
			}
			// Keep the local alias as a label so a report can still show the name
			// the manifest used, without it ever being the security identity.
			if alias := yarnDescriptorName(e.descriptors[0]); alias != "" && alias != name {
				if n.Attr == nil {
					n.Attr = map[string]string{}
				}
				n.Attr["npm.alias"] = alias
			}
			byName[name] = append(byName[name], id)
		}
		// Index the node under every descriptor that resolves to it — the alias
		// descriptor (so a dependant that references the alias links) AND, for an
		// alias, the real name@range (so a reference by the true coordinate links).
		for _, d := range e.descriptors {
			dn, dr := splitYarnDescriptor(d)
			if dn == "" {
				continue
			}
			descNode[dn+"@"+stripNpmProto(dr)] = id
			if inner, innerRange := aliasTarget(dr); inner != "" {
				descNode[inner+"@"+innerRange] = id
			}
		}
	}

	// Edges between resolved packages.
	for _, e := range entries {
		if e.version == "" || len(e.descriptors) == 0 {
			continue
		}
		fromID := purl.NewNpm(yarnResolvedName(e.descriptors[0]), e.version).
			WithSource(classifyResolved(e.resolved)).String()
		for _, dn := range sortedStrKeys(e.deps) {
			if to, ok := resolveYarnDep(descNode, byName, dn, e.deps[dn]); ok {
				g.AddEdge(fromID, to, graph.EdgeDependsOn)
			}
		}
	}

	rootID := yarnAttachRoot(g, manifestRaw, dir, descNode, byName)
	assignDepths(g, rootID)
	return g, nil
}

// resolveYarnDep resolves a dependency (name, range) to a node ID: an exact
// normalized-descriptor match first, then the single-version fallback.
func resolveYarnDep(descNode map[string]string, byName map[string][]string, name, rng string) (string, bool) {
	if id, ok := descNode[name+"@"+stripNpmProto(rng)]; ok {
		return id, true
	}
	if ids := byName[name]; len(ids) == 1 {
		return ids[0], true
	}
	return "", false
}

// yarnAttachRoot creates the project root from package.json and links its direct
// dependencies, marking each linked node Direct. With no manifest — or a manifest
// whose declared deps matched nothing — it falls back to connecting the root to
// every package nothing else depends on (in-degree 0), the same topology anchor
// Cargo uses (D-50), so the tree still ladders instead of collapsing to depth 0.
func yarnAttachRoot(g *graph.Graph, manifestRaw []byte, dir string, descNode map[string]string, byName map[string][]string) string {
	var m struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if len(manifestRaw) > 0 {
		_ = json.Unmarshal(manifestRaw, &m)
	}

	name := m.Name
	if name == "" {
		if dir != "" {
			name = filepath.Base(dir)
		}
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "root"
		}
	}
	version := firstNonEmpty(m.Version, "0.0.0")
	rootID := purl.NewNpm(name, version).String()
	g.AddNode(&graph.Node{
		ID: rootID, Ecosystem: "npm", Name: name, Version: version, Depth: 0,
		Attr: map[string]string{"npm.path": "."},
	})
	g.MarkRoot(rootID)

	// The root's own dependencies, devDependencies, optional and peer deps are all
	// installed by yarn, so all are direct edges of the root (a dependency's OWN
	// devDeps are never installed downstream — but those are not in this set).
	direct := map[string]string{}
	for _, mp := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies, m.PeerDependencies} {
		for n, r := range mp {
			direct[n] = r
		}
	}
	linked := 0
	for _, dn := range sortedStrKeys(direct) {
		nm, constraint := resolveNpmAlias(dn, direct[dn])
		if id, ok := resolveYarnDep(descNode, byName, nm, constraint); ok {
			g.AddEdge(rootID, id, graph.EdgeDependsOn)
			if n := g.Get(id); n != nil {
				n.Direct = true
			}
			linked++
		}
	}

	// No manifest edge landed: anchor on topology so depth still assigns.
	if linked == 0 {
		for _, id := range inDegreeZeroIDs(g, rootID) {
			g.AddEdge(rootID, id, graph.EdgeDependsOn)
			if n := g.Get(id); n != nil {
				n.Direct = true
			}
		}
	}
	return rootID
}

// inDegreeZeroIDs returns every package node with no incoming depends-on edge,
// excluding the root — the packages nothing else requires, i.e. the tree's own
// entry points when a manifest cannot name them.
func inDegreeZeroIDs(g *graph.Graph, rootID string) []string {
	indeg := map[string]int{}
	for _, n := range g.SortedNodes() {
		indeg[n.ID] += 0
	}
	for _, e := range g.SortedEdges() {
		if e.Type == graph.EdgeDependsOn {
			indeg[e.To]++
		}
	}
	var out []string
	for _, n := range g.SortedNodes() {
		if n.ID != rootID && n.Kind == graph.KindPackage && indeg[n.ID] == 0 {
			out = append(out, n.ID)
		}
	}
	sort.Strings(out)
	return out
}

// ---- lexing --------------------------------------------------------------

// scanYarnLock tokenizes a yarn.lock (either dialect) into its resolved blocks.
// It is intentionally forgiving: a hostile or truncated lockfile must yield a
// partial, self-consistent set of entries, never a panic (D-33).
func scanYarnLock(raw []byte) []yarnEntry {
	var entries []yarnEntry
	var cur *yarnEntry
	inDeps := false

	flush := func() {
		if cur != nil {
			entries = append(entries, *cur)
		}
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		line := strings.TrimRight(ln, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		switch {
		case indent == 0:
			flush()
			cur = &yarnEntry{deps: map[string]string{}}
			cur.descriptors = parseYarnHeader(trimmed)
			inDeps = false
		case cur == nil:
			continue
		case indent >= 4 && inDeps:
			if dn, dr := parseYarnDepLine(trimmed); dn != "" {
				cur.deps[dn] = dr
			}
		default: // a nested field (version, resolved, dependencies:, …)
			key, val := parseYarnField(trimmed)
			switch key {
			case "version":
				cur.version = val
			case "resolved", "resolution":
				if cur.resolved == "" {
					cur.resolved = val
				}
			case "dependencies", "optionalDependencies":
				inDeps = true
			default:
				inDeps = false
			}
		}
	}
	flush()
	return entries
}

// parseYarnHeader turns a descriptor header line into its descriptor strings,
// spanning both dialects: v1 quotes each descriptor ("a", "b":), berry joins
// them in one quoted string ("a, b":). Splitting on ", " then trimming quotes
// from each part handles both.
func parseYarnHeader(s string) []string {
	s = strings.TrimSuffix(s, ":")
	parts := strings.Split(s, ", ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.Trim(strings.TrimSpace(p), `"`); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseYarnField splits a nested "key value" or "key: value" line, unquoting the
// value. It is used for version / resolved / resolution and to detect the
// dependencies blocks.
func parseYarnField(s string) (key, val string) {
	i := strings.IndexAny(s, " :")
	if i < 0 {
		return s, ""
	}
	key = s[:i]
	rest := strings.TrimSpace(s[i:])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
	return key, strings.Trim(rest, `"`)
}

// parseYarnDepLine splits a dependency line into (name, range). Package names
// never contain spaces, so the last space separates name from range in both
// dialects — v1 `name "range"`, berry `"name": "range"`.
func parseYarnDepLine(s string) (name, rng string) {
	i := strings.LastIndex(s, " ")
	if i < 0 {
		return "", ""
	}
	name = strings.TrimSpace(s[:i])
	name = strings.Trim(strings.TrimSuffix(name, ":"), `"`)
	rng = strings.Trim(strings.TrimSpace(s[i+1:]), `"`)
	return name, rng
}

// splitYarnDescriptor splits "name@range" (or "@scope/name@range") into its name
// and range. The separating '@' is the first one after any leading scope '@'.
func splitYarnDescriptor(desc string) (name, rng string) {
	body, scoped := desc, false
	if strings.HasPrefix(desc, "@") {
		body, scoped = desc[1:], true
	}
	i := strings.IndexByte(body, '@')
	if i < 0 {
		return desc, ""
	}
	if scoped {
		return "@" + body[:i], body[i+1:]
	}
	return body[:i], body[i+1:]
}

// yarnDescriptorName is splitYarnDescriptor's name half — the LOCAL name a
// descriptor uses, which for an alias is the alias, not the real package.
func yarnDescriptorName(desc string) string {
	n, _ := splitYarnDescriptor(desc)
	return n
}

// yarnResolvedName is the descriptor's true package name for security identity:
// it unwraps a yarn alias ("alias@npm:REALNAME@range") to REALNAME, while a
// plain range ("foo@npm:^1", "@babel/core@npm:^7") keeps its own name. This is
// the name OSV, the registry, and typosquat must see — the alias would match a
// different package that merely shares the local name (OPU-08).
func yarnResolvedName(desc string) string {
	name, rng := splitYarnDescriptor(desc)
	if inner, _ := aliasTarget(rng); inner != "" {
		return inner
	}
	return name
}

// aliasTarget reports the real package a yarn `npm:` alias range points at.
// A range is an alias only when, after dropping the "npm:" protocol, it still
// splits into BOTH an inner name and an inner range ("@elastic/elasticsearch@8.19.1"
// -> "@elastic/elasticsearch", "8.19.1"). A bare range ("^1.2.3") has no inner
// name and is not an alias.
func aliasTarget(rng string) (name, innerRange string) {
	if !strings.HasPrefix(rng, "npm:") {
		return "", ""
	}
	inner, ir := splitYarnDescriptor(stripNpmProto(rng))
	if inner != "" && ir != "" {
		return inner, ir
	}
	return "", ""
}

// isNonPackageYarnEntry reports whether a scanned block is not a resolved
// registry package that should become a node: Berry's `__metadata` header, or a
// workspace/portal/link SELF-entry (the project or a workspace member describing
// its own local location). The real root comes from package.json; these would
// otherwise be phantom nodes (OPU-07).
func isNonPackageYarnEntry(e yarnEntry) bool {
	if len(e.descriptors) == 0 {
		return true
	}
	name, rng := splitYarnDescriptor(e.descriptors[0])
	if name == "__metadata" {
		return true
	}
	for _, proto := range []string{"workspace:", "portal:", "link:"} {
		if strings.HasPrefix(rng, proto) {
			return true
		}
	}
	return false
}

// stripNpmProto drops berry's "npm:" range protocol so a berry descriptor
// ("react@npm:^18") and a v1/manifest range ("^18") normalize to one key.
func stripNpmProto(rng string) string { return strings.TrimPrefix(rng, "npm:") }

// sortedStrKeys returns a string-map's keys in stable order (determinism, D-13).
func sortedStrKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
