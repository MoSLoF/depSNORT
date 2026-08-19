package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// package.json manifest support — the no-lockfile fallback.
//
// A package.json with dependencies but no package-lock.json is a MANIFEST, not a
// resolved tree: it declares names and semver ranges with no pinned versions.
// So it produces a root whose declared deps ride on graph.AttrDeclaredDeps, and
// transitive expansion (D-44) presumes a version for each. The trial-by-fire
// found this on a real project (an npm app committed without its lockfile),
// exactly the manifest-only gap the PyPI pyproject fix closed.
//
// package-lock.json is always preferred when present (it is a resolved tree);
// this path runs only when the lock is absent.

const manifestName = "package.json"

// manifestPath resolves a dir or file to a package.json that declares
// dependencies and has NO sibling lockfile, else "".
func manifestPath(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	dir := path
	if !info.IsDir() {
		if filepath.Base(path) != manifestName {
			return ""
		}
		dir = filepath.Dir(path)
	}
	// A resolved lockfile beside it wins; this fallback is only for the case where
	// neither a package-lock.json nor a yarn.lock is present.
	if _, err := os.Stat(filepath.Join(dir, lockName)); err == nil {
		return ""
	}
	if _, err := os.Stat(filepath.Join(dir, yarnLockName)); err == nil {
		return ""
	}
	p := filepath.Join(dir, manifestName)
	if !manifestDeclaresDeps(p) {
		return ""
	}
	return p
}

type packageManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func manifestDeclaresDeps(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var m packageManifest
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	return len(m.Dependencies)+len(m.OptionalDependencies) > 0
}

func parseManifest(path string, raw []byte) (*graph.Graph, error) {
	var m packageManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	name := m.Name
	if name == "" {
		name = filepath.Base(filepath.Dir(path))
	}
	version := m.Version
	if version == "" {
		version = "0.0.0"
	}
	g := graph.New()
	rootID := purl.NewNpm(name, version).String()
	root := g.AddNode(&graph.Node{
		ID: rootID, Ecosystem: "npm", Name: name, Version: version, Depth: 0,
		Attr: map[string]string{"npm.source": manifestName},
	})
	g.MarkRoot(rootID)

	// Runtime + optional deps are the declared set; devDependencies are excluded
	// (a consumer never installs a package's devDeps transitively, and for the
	// root manifest they are the project's own tooling, not its dependency tree).
	var declared []graph.DeclaredDep
	var names []string
	add := func(deps map[string]string) {
		for n, rng := range deps {
			nm, constraint := resolveNpmAlias(n, rng)
			declared = append(declared, graph.DeclaredDep{Name: nm, Constraint: constraint})
			names = append(names, nm)
		}
	}
	add(m.Dependencies)
	add(m.OptionalDependencies)
	if len(declared) == 0 {
		return nil, errNoManifestDeps
	}
	sort.Slice(declared, func(i, j int) bool { return declared[i].Name < declared[j].Name })
	sort.Strings(names)
	root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(declared)
	root.Attr[graph.AttrUnresolved] = joinCSV(names)
	root.Attr[graph.AttrUnresolvedCount] = itoaN(len(names))
	root.Attr[graph.AttrFlatResolution] = "npm"
	return g, nil
}

var errNoManifestDeps = errNoDeps

var errNoDeps = &noDepsError{}

type noDepsError struct{}

func (*noDepsError) Error() string { return "npm: package.json declares no dependencies" }

func joinCSV(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func itoaN(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
