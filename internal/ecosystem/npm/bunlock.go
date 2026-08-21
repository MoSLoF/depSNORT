package npm

// bun.lock support.
//
// bun.lock is the text lockfile Bun writes (default since Bun 1.2, replacing the
// binary bun.lockb which depsnort cannot read and only discloses as a gap). It
// is a fully-resolved graph: a `workspaces` table giving the root project's
// direct dependencies, and a `packages` table with one entry per resolved
// package carrying its own dependency set — so, like package-lock.json, the
// transitive closure is observed fact, not presumption.
//
// The format is JSONC (JSON with trailing commas, and comments permitted), which
// Go's encoding/json rejects. Rather than hand-scan nested JSON, this sanitizes
// the JSONC extensions away (a small string-aware pass) and then uses the
// standard library parser — encoding/json is stdlib, so this respects D-10 (no
// third-party parser) while being far more robust than re-implementing a JSON
// reader. Each `packages` entry is a heterogeneous tuple
// `["name@version", registry, { …metadata… }, "hash"]`; only the descriptor and
// the metadata object's dependency maps feed the graph.

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

const bunLockName = "bun.lock"

// bunLockPath resolves path (a dir or a file) to a bun.lock path, or "".
func bunLockPath(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		p := filepath.Join(path, bunLockName)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
		return ""
	}
	if filepath.Base(path) == bunLockName {
		return path
	}
	return ""
}

type bunWorkspace struct {
	Name             string            `json:"name"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	OptionalDeps     map[string]string `json:"optionalDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

type bunLockfile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Workspaces      map[string]bunWorkspace    `json:"workspaces"`
	Packages        map[string]json.RawMessage `json:"packages"`
}

// bunPkgMeta is the metadata object embedded in a packages[] tuple. A
// dependency's OWN devDependencies are not installed downstream (npm/bun
// semantics, mirroring resolveV2), so they are intentionally not edges.
type bunPkgMeta struct {
	Dependencies     map[string]string `json:"dependencies"`
	OptionalDeps     map[string]string `json:"optionalDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

func parseBunLock(raw []byte) (*graph.Graph, error) {
	var lf bunLockfile
	if err := json.Unmarshal(stripJSONC(raw), &lf); err != nil {
		return nil, fmt.Errorf("npm: parsing %s: %w", bunLockName, err)
	}

	g := graph.New()

	rootWs := lf.Workspaces[""]
	rootName := firstNonEmpty(rootWs.Name, "root")
	rootVer := "0.0.0"
	rootID := purl.NewNpm(rootName, rootVer).String()
	g.AddNode(&graph.Node{
		ID: rootID, Ecosystem: "npm", Name: rootName, Version: rootVer, Depth: 0,
		Attr: map[string]string{"npm.path": "."},
	})
	g.MarkRoot(rootID)

	// Root direct set: the root workspace's declared deps (all classes; bun, like
	// npm, installs the root project's devDependencies).
	directNames := mergeKeys(rootWs.Dependencies, rootWs.DevDependencies, rootWs.OptionalDeps, rootWs.PeerDependencies)

	type bunPkg struct {
		name, version    string
		srcClass, srcRef string
		deps             map[string]bool
	}
	pkgs := map[string]*bunPkg{}  // packages-map key -> parsed package
	byName := map[string]string{} // package name -> node ID (last wins on dupes)

	pkgKeys := make([]string, 0, len(lf.Packages))
	for k := range lf.Packages {
		pkgKeys = append(pkgKeys, k)
	}
	sort.Strings(pkgKeys) // determinism (D-09): map order is randomized

	for _, key := range pkgKeys {
		var tuple []json.RawMessage
		if err := json.Unmarshal(lf.Packages[key], &tuple); err != nil || len(tuple) == 0 {
			continue
		}
		var descriptor string
		_ = json.Unmarshal(tuple[0], &descriptor)
		name, ver := splitBunDescriptor(descriptor)
		if name == "" {
			continue
		}
		// The metadata object is the first tuple element that is a JSON object.
		var meta bunPkgMeta
		for _, el := range tuple[1:] {
			if t := strings.TrimSpace(string(el)); strings.HasPrefix(t, "{") {
				_ = json.Unmarshal(el, &meta)
				break
			}
		}
		cls, ref := bunSource(ver)
		pkgs[key] = &bunPkg{
			name: name, version: ver, srcClass: cls, srcRef: ref,
			deps: mergeKeys(meta.Dependencies, meta.OptionalDeps, meta.PeerDependencies),
		}
	}

	// Nodes.
	keys := make([]string, 0, len(pkgs))
	for k := range pkgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := pkgs[key]
		ver := firstNonEmpty(p.version, "0.0.0")
		id := purl.NewNpm(p.name, ver).String()
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "npm", Name: p.name, Version: ver, Direct: directNames[p.name],
		})
		if p.srcClass != "" {
			n.SetSource(p.srcClass, p.srcRef)
		}
		byName[p.name] = id
	}

	addEdge := func(fromID, depName string) {
		if toID, ok := byName[depName]; ok {
			g.AddEdge(fromID, toID, graph.EdgeDependsOn)
		}
	}
	for _, dep := range sortedSet(directNames) {
		addEdge(rootID, dep)
	}
	for _, key := range keys {
		p := pkgs[key]
		fromID := byName[p.name]
		for _, dep := range sortedSet(p.deps) {
			addEdge(fromID, dep)
		}
	}

	assignDepths(g, rootID)
	return g, nil
}

// splitBunDescriptor splits a bun descriptor "name@version" into its parts,
// honoring scoped names ("@scope/pkg@1.2.3") and leaving aliased/git/workspace
// version strings intact for bunSource to classify.
func splitBunDescriptor(d string) (name, ver string) {
	if d == "" {
		return "", ""
	}
	at := -1
	if strings.HasPrefix(d, "@") {
		if i := strings.IndexByte(d[1:], '@'); i >= 0 {
			at = 1 + i
		}
	} else {
		if i := strings.IndexByte(d, '@'); i >= 0 {
			at = i
		}
	}
	if at < 0 {
		return d, ""
	}
	return d[:at], d[at+1:]
}

// bunSource classifies a descriptor's version part into an ecosystem-neutral
// provenance class, mirroring classifyResolved's intent for the bun descriptor
// vocabulary (github:/git+/workspace:/file:/link:/http(s):/ and plain semver).
func bunSource(ver string) (class, ref string) {
	v := strings.ToLower(strings.TrimSpace(ver))
	switch {
	case v == "":
		return "", ""
	case strings.HasPrefix(v, "github:"), strings.HasPrefix(v, "git+"),
		strings.HasPrefix(v, "git:"), strings.HasPrefix(v, "git@"):
		return graph.SourceGit, ver
	case strings.HasPrefix(v, "workspace:"), strings.HasPrefix(v, "file:"), strings.HasPrefix(v, "link:"):
		return graph.SourcePath, ver
	case strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "https://"):
		return graph.SourceURL, ver
	default:
		// Plain semver or an `npm:` alias — a registry coordinate an advisory
		// feed can be queried about (recorded positively, like poetry's registry
		// default), which is the only property this classification asserts.
		return graph.SourceRegistry, "https://registry.npmjs.org"
	}
}

// stripJSONC removes the JSONC extensions Go's encoding/json rejects — line and
// block comments, and trailing commas — in two string-aware passes, so a comma
// or `//` inside a string value is preserved.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, b[i]) // keep the newline
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++ // consume the '*'; loop's i++ consumes the '/'
		default:
			out = append(out, c)
		}
	}
	return stripTrailingCommas(out)
}

func stripTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue // drop the trailing comma
			}
		}
		out = append(out, c)
	}
	return out
}
