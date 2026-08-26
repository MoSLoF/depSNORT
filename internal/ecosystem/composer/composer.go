// Package composer is the Composer (PHP) ecosystem adapter. It parses
// composer.lock and builds the dependency graph.
//
// Install-time attack vectors:
//   - composer.json "scripts" section: lifecycle hooks (post-install-cmd,
//     post-update-cmd, etc.) run arbitrary commands at install time
//   - Composer plugins (type: "composer-plugin"): auto-loaded and executed
//     during every Composer operation
//
// Nothing here installs or executes anything (Decision D-04).
package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/securefs"
)

// Adapter implements ecosystem.Adapter for Composer.
type Adapter struct{}

// New returns a Composer adapter.
func New() *Adapter { return &Adapter{} }

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "composer" }

const (
	composerLockName     = "composer.lock"
	composerManifestName = "composer.json"
)

// Detect implements ecosystem.Adapter. A composer.lock claims the project (a
// resolved tree); failing that, a composer.json declaring non-platform
// dependencies claims it as a manifest-only project — the same lock-or-manifest
// handling npm and PyPI already have. Without this, a Composer library or any
// project committed without a lock read as "nothing to scan" (OPU-11).
func (*Adapter) Detect(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return fileExists(filepath.Join(path, composerLockName)) ||
			manifestDeclaresDeps(filepath.Join(path, composerManifestName))
	}
	base := filepath.Base(path)
	return base == composerLockName || (base == composerManifestName && manifestDeclaresDeps(path))
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Resolve implements ecosystem.Adapter. composer.lock takes precedence (observed
// versions beat presumed); with no lock, a composer.json is parsed manifest-only
// and its declared deps ride to the expansion tier (D-44), exactly as a
// lock-less package.json or pyproject.toml is handled.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("composer: %w", err)
	}
	if !info.IsDir() {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("composer: reading %s: %w", filepath.Base(path), err)
		}
		if filepath.Base(path) == composerManifestName {
			return parseComposerManifest(path, raw)
		}
		return parseComposerLock(path, raw)
	}
	if lock := filepath.Join(path, composerLockName); fileExists(lock) {
		raw, err := os.ReadFile(lock)
		if err != nil {
			return nil, fmt.Errorf("composer: reading %s: %w", composerLockName, err)
		}
		return parseComposerLock(path, raw)
	}
	manifest := filepath.Join(path, composerManifestName)
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return nil, fmt.Errorf("composer: reading %s: %w", composerManifestName, err)
	}
	return parseComposerManifest(path, raw)
}

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Type    string            `json:"type"`
	Require map[string]string `json:"require"`
	// Dist and Source record where the package came from (D-41). Composer
	// writes both: `dist` is the artifact actually installed, `source` the
	// repository behind it. A path repository and a git-only package are
	// visible here and nowhere else.
	Dist   composerRef `json:"dist"`
	Source composerRef `json:"source"`
}

type composerRef struct {
	Type      string `json:"type"` // "zip", "git", "path", ...
	URL       string `json:"url"`
	Reference string `json:"reference"`
}

func parseComposerLock(path string, raw []byte) (*graph.Graph, error) {
	var lf composerLock
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("composer: parsing %s: %w", composerLockName, err)
	}

	g := graph.New()
	root := rootNode(g, path)

	byName := map[string]string{} // package name -> node ID
	addPkgs := func(pkgs []composerPkg, section string) {
		for _, p := range pkgs {
			if p.Name == "" || p.Version == "" {
				continue
			}
			version := strings.TrimPrefix(p.Version, "v")
			id := purl.NewComposer(p.Name, version).String()
			attr := map[string]string{
				"composer.source":  composerLockName,
				"composer.section": section,
			}
			if p.Type != "" {
				attr["composer.type"] = p.Type
			}
			n := g.AddNode(&graph.Node{
				ID: id, Ecosystem: "composer", Name: p.Name, Version: version,
				Direct: true, Depth: 1,
				Attr: attr,
			})
			n.SetSource(classifyPkgSource(p))
			byName[p.Name] = id
			g.AddEdge(root.ID, id, graph.EdgeDependsOn)
		}
	}
	addPkgs(lf.Packages, "packages")
	addPkgs(lf.PackagesDev, "packages-dev")

	if g.Len() == 1 {
		return nil, fmt.Errorf("composer: %s contained no resolved packages", composerLockName)
	}

	// Build inter-package edges from require sections.
	allPkgs := append(lf.Packages, lf.PackagesDev...)
	for _, p := range allPkgs {
		fromID, ok := byName[p.Name]
		if !ok {
			continue
		}
		for dep := range p.Require {
			toID, ok := byName[dep]
			if !ok || toID == fromID {
				continue
			}
			g.AddEdge(fromID, toID, graph.EdgeDependsOn)
		}
	}

	// Re-mark direct: only packages not required by another package are direct.
	hasInbound := map[string]bool{}
	for _, e := range g.SortedEdges() {
		if e.From != root.ID && e.Type == graph.EdgeDependsOn {
			hasInbound[e.To] = true
		}
	}
	for _, n := range g.SortedNodes() {
		if n.ID == root.ID {
			continue
		}
		if hasInbound[n.ID] {
			n.Direct = false
			g.RemoveEdge(root.ID, n.ID, graph.EdgeDependsOn)
		}
	}

	assignDepths(g, root.ID)
	return g, nil
}

// composerJSONDeps is the subset of a composer.json read for manifest-only
// resolution: the declared require blocks, names and constraints only.
type composerJSONDeps struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// manifestDeclaresDeps reports whether a composer.json at p declares at least one
// non-platform dependency — the gate for claiming a lock-less project.
func manifestDeclaresDeps(p string) bool {
	raw, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	var m composerJSONDeps
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	for _, reqs := range []map[string]string{m.Require, m.RequireDev} {
		for name := range reqs {
			if !isComposerPlatformPackage(name) {
				return true
			}
		}
	}
	return false
}

// parseComposerManifest builds a manifest-only graph from a composer.json with no
// lockfile: the project root plus its declared (name + constraint) dependencies,
// which the expansion tier presumes or asserts a version for (D-44). Platform
// requirements (php, ext-*, …) are dropped — they name the runtime, not an
// installable package. Mirrors npm/manifest.go and pypi/parsePyproject.
func parseComposerManifest(path string, raw []byte) (*graph.Graph, error) {
	var m composerJSONDeps
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("composer: parsing %s: %w", composerManifestName, err)
	}

	g := graph.New()
	root := rootNode(g, path)

	var declared []graph.DeclaredDep
	var names []string
	seen := map[string]bool{}
	add := func(reqs map[string]string) {
		for name, constraint := range reqs {
			if isComposerPlatformPackage(name) {
				continue
			}
			// Packagist names are case-insensitive; lowercase so a manifest's
			// "Monolog/Monolog" and a dependency's "monolog/monolog" are one node
			// (the D-15 leak class), matching WalkSource.Identify.
			canon := lower(name)
			if seen[canon] {
				continue
			}
			seen[canon] = true
			declared = append(declared, graph.DeclaredDep{Name: canon, Constraint: constraint})
			names = append(names, canon)
		}
	}
	add(m.Require)
	add(m.RequireDev)
	if len(declared) == 0 {
		return nil, errNoComposerManifestDeps
	}
	sort.Slice(declared, func(i, j int) bool { return declared[i].Name < declared[j].Name })
	sort.Strings(names)

	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	root.Attr["composer.source"] = composerManifestName
	root.Attr[graph.AttrDeclaredDeps] = graph.EncodeDeclaredDeps(declared)
	// Surfaced as a coverage fact so a manifest-only project degrades coverage
	// (its versions are presumed, not observed) rather than reading as a clean,
	// fully-resolved tree — the same disclosure npm/PyPI make.
	root.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
	root.Attr[graph.AttrUnresolvedCount] = fmt.Sprintf("%d", len(names))
	root.Attr[graph.AttrFlatResolution] = "composer"
	return g, nil
}

var errNoComposerManifestDeps = fmt.Errorf("composer: %s declares no non-platform dependencies", composerManifestName)

// isComposerPlatformPackage mirrors registry.isPlatformPackage: a require key
// that names the runtime (php, hhvm, ext-*, lib-*, composer-*) or lacks a
// vendor/name slash is a platform token, not an installable package.
func isComposerPlatformPackage(name string) bool {
	l := strings.ToLower(name)
	switch {
	case l == "php", l == "hhvm":
		return true
	case strings.HasPrefix(l, "ext-"), strings.HasPrefix(l, "lib-"), strings.HasPrefix(l, "composer-"):
		return true
	case !strings.Contains(l, "/"):
		return true
	}
	return false
}

// classifyPkgSource maps a composer.lock entry's dist/source blocks onto an
// ecosystem-neutral provenance class (Decision D-41).
//
// dist wins when both are present because dist is what Composer actually
// installs: a package with a git `source` and a Packagist `dist` zip was
// installed from the zip, and the zip is the artifact an advisory feed indexes.
// A `path` dist is a local repository — symlinked or copied source that was
// never published. A package with only a `source` block was cloned, so the
// repository IS the artifact.
func classifyPkgSource(p composerPkg) (class, ref string) {
	switch p.Dist.Type {
	case "path":
		return graph.SourcePath, p.Dist.URL
	case "git", "hg", "svn":
		return graph.SourceGit, p.Dist.URL
	case "zip", "tar", "gzip", "phar", "rar", "xz":
		return graph.SourceRegistry, p.Dist.URL
	}
	if p.Dist.Type == "" {
		switch p.Source.Type {
		case "git", "hg", "svn":
			return graph.SourceGit, p.Source.URL
		case "path":
			return graph.SourcePath, p.Source.URL
		}
	}
	if p.Dist.URL != "" {
		return graph.ClassifyRef(p.Dist.URL), p.Dist.URL
	}
	return "", ""
}

// composerManifest is the subset of a composer.json we read for install-surface.
type composerManifest struct {
	Type    string                     `json:"type"`
	Scripts map[string]json.RawMessage `json:"scripts"`
	Extra   struct {
		Class string `json:"class"`
	} `json:"extra"`
	Autoload struct {
		PSR4 map[string]json.RawMessage `json:"psr-4"`
	} `json:"autoload"`
}

// ExtractInstallSurface implements ecosystem.InstallSurfaceExtractor.
//
// The ROOT project's composer.json is always read from the project directory —
// its lifecycle scripts and plugin type are install-time facts that exist in a
// bare source checkout, independent of whether `composer install` has populated
// vendor/. (The prior implementation bailed out entirely when vendor/ was
// absent, so a root project's own post-install cradle went unexamined — the
// silent all-clear that Decision D-27 closes.)
//
// Transitive packages are read from vendor/<pkg>/composer.json only when that
// directory is present, mirroring npm/pypi: uninstalled dependency source is
// not on disk and is left unrepresented rather than guessed at.
//
// For a composer-plugin, the declared entrypoint class is resolved through the
// package's PSR-4 autoload map and its PHP source is scanned — a plugin's
// activate() is install-time code even when no lifecycle script is declared.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	rootDir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		rootDir = filepath.Dir(path)
	}
	vendorDir := filepath.Join(rootDir, "vendor")
	vendorPresent := false
	if info, err := os.Stat(vendorDir); err == nil && info.IsDir() {
		vendorPresent = true
	}

	// Contained reader for every manifest and PSR-4 source read below (F-03).
	// Transitive baseDirs are built from lockfile package names and PSR-4 dirs
	// from composer.json — both untrusted — so a name like "../../etc" or a
	// symlinked vendor entry is refused here rather than followed off-tree.
	reader, err := securefs.NewReader(rootDir)
	if err != nil {
		return fmt.Errorf("composer: %w", err)
	}

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}

	// Refused reads become typed gaps rather than silent skips (R-01).
	var gaps instsurf.Gaps
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "composer" {
			continue
		}

		// Paths handed to the contained reader are RELATIVE TO THE SCAN ROOT,
		// which is what securefs.Reader expects: it joins a relative path onto
		// its own root and refuses anything that escapes.
		//
		// These used to be joined with rootDir first. With an absolute scan
		// path that is harmless — securefs leaves absolute paths alone — but
		// with a RELATIVE one, "testdata/proj/composer.json" was joined onto
		// the root a second time, landing at
		// "<root>/testdata/proj/composer.json", outside the root, and refused.
		// So `depsnort scan ./path` silently lost the root project's own
		// manifest while `depsnort scan /abs/path` analyzed it — the same tree
		// scanned two ways gave two different verdicts, and the block-class
		// cradle in the adversarial composer fixture went undetected through
		// the relative path.
		//
		// The refusal WAS disclosed as a coverage gap, which is why this was a
		// lost detection rather than a silent all-clear. It was still a
		// detection the tool is supposed to make (D-27).
		var manifestPath, baseDir string
		if roots[n.ID] {
			baseDir = "."
			manifestPath = "composer.json"
		} else {
			if !vendorPresent {
				continue // uninstalled transitive source is not on disk
			}
			baseDir = filepath.Join("vendor", n.Name)
			manifestPath = filepath.Join(baseDir, "composer.json")
		}

		raw, err := reader.ReadFile(manifestPath)
		if err != nil {
			gaps.Add(n.ID, manifestPath, err)
			continue
		}
		var manifest composerManifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			gaps.AddReason(n.ID, manifestPath, instsurf.GapParse, err)
			continue
		}

		flatScripts := flattenScripts(manifest.Scripts)
		var pluginSource string
		if manifest.Type == "composer-plugin" {
			var perr error
			pluginSource, perr = pluginEntrypointSource(reader, baseDir, manifest)
			// A plugin auto-executes on every Composer operation. If its
			// entrypoint exists but we were refused, that is the single most
			// important file in the package and its absence must be visible.
			if perr != nil {
				gaps.Add(n.ID, baseDir, perr)
			}
		}

		surface := installsurface.AnalyzePHP(flatScripts, manifest.Type, pluginSource)
		if len(surface.Hooks) > 0 {
			addSurfaceToGraph(g, n, surface)
		}
	}
	return gaps.Err()
}

// flattenScripts normalizes composer.json "scripts" values, which may each be a
// string or an array of strings, into a single command string per event.
func flattenScripts(scripts map[string]json.RawMessage) map[string]string {
	flat := map[string]string{}
	for name, raw := range scripts {
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			flat[name] = single
			continue
		}
		var multi []string
		if err := json.Unmarshal(raw, &multi); err == nil {
			flat[name] = strings.Join(multi, "; ")
		}
	}
	return flat
}

// pluginEntrypointSource resolves a composer-plugin's declared class to its PHP
// source file via the package's PSR-4 autoload map and returns its contents.
// Returns "" when the class is undeclared or the file cannot be located — the
// caller treats that as "plugin present, source unread" rather than clean.
// It returns a non-nil error only when a candidate file EXISTED but could not be
// read (containment refusal, special file, oversize) — an ordinary "not on disk"
// is reported as ("", nil), because most plugins are simply not installed in a
// source checkout (R-01).
func pluginEntrypointSource(reader *securefs.Reader, baseDir string, m composerManifest) (string, error) {
	class := strings.TrimSpace(m.Extra.Class)
	if class == "" {
		return "", nil
	}
	var refusal error
	try := func(path string) (string, bool) {
		b, err := reader.ReadFile(path)
		if err == nil {
			return string(b), true
		}
		if _, isGap := instsurf.Classify(err); isGap && refusal == nil {
			refusal = err
		}
		return "", false
	}
	// FQCN uses backslash separators: Vendor\Package\Plugin.
	classPath := strings.ReplaceAll(strings.TrimLeft(class, `\`), `\`, "/")

	// PSR-4: namespace prefix -> one or more directories. Longest matching
	// prefix wins (Composer's own resolution order).
	type mapping struct {
		prefix string
		dirs   []string
	}
	var maps []mapping
	for pfx, rawDirs := range m.Autoload.PSR4 {
		maps = append(maps, mapping{
			prefix: strings.ReplaceAll(strings.TrimRight(pfx, `\`), `\`, "/"),
			dirs:   psr4Dirs(rawDirs),
		})
	}
	sort.Slice(maps, func(i, j int) bool { return len(maps[i].prefix) > len(maps[j].prefix) })

	for _, mp := range maps {
		if mp.prefix == "" || !strings.HasPrefix(classPath, mp.prefix) {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(classPath, mp.prefix), "/")
		for _, dir := range mp.dirs {
			file := filepath.Join(baseDir, filepath.FromSlash(dir), filepath.FromSlash(rel)+".php")
			if src, ok := try(file); ok {
				return src, nil
			}
		}
	}

	// Fallback: the conventional src/<ClassBase>.php with no autoload declared.
	base := classPath
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	for _, guess := range []string{
		filepath.Join(baseDir, "src", base+".php"),
		filepath.Join(baseDir, base+".php"),
	} {
		if src, ok := try(guess); ok {
			return src, nil
		}
	}
	return "", refusal
}

// psr4Dirs decodes a PSR-4 autoload value, which may be a single directory
// string or an array of directory strings.
func psr4Dirs(raw json.RawMessage) []string {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		return multi
	}
	return nil
}

func addSurfaceToGraph(g *graph.Graph, pkg *graph.Node, s installsurface.Surface) {
	for _, h := range s.Hooks {
		hookID := "hook:" + pkg.ID + "#" + sanitize(h.Name)
		hookNode := g.AddNode(&graph.Node{
			ID:        hookID,
			Kind:      graph.KindInstallHook,
			Ecosystem: pkg.Ecosystem,
			Name:      h.Name,
			Depth:     pkg.Depth,
			Attr: map[string]string{
				"hook.command": truncate(h.Command, 400),
				"hook.package": pkg.ID,
			},
		})
		setCaps(hookNode, h.Caps)
		if len(h.Evidence) > 0 {
			hookNode.Attr["hook.evidence"] = strings.Join(h.Evidence, ",")
		}
		g.AddEdge(pkg.ID, hookID, graph.EdgeDeclaresHook)

		// D-152: the worm loop. Drawn here as well as in instsurf.AddToGraph
		// because npm, PyPI and Composer each hand-roll a near-verbatim copy of
		// that function; wiring the edge only in the shared helper left the ONE
		// ecosystem Shai-Hulud actually targets without it, so a live npm worm
		// produced a VC-002k finding over a graph that showed no loop. The
		// conformance test in internal/ecosystem/conformance keeps the copies
		// from drifting apart again.
		if h.HasCap(installsurface.CapPropagate) {
			g.AddEdge(hookID, pkg.ID, graph.EdgeRepublish)
		}

		for _, a := range h.Artifacts {
			artID := "artifact:" + pkg.ID + "#" + a.Ref
			an := g.AddNode(&graph.Node{
				ID:        artID,
				Kind:      graph.KindReferencedArtifact,
				Ecosystem: pkg.Ecosystem,
				Name:      a.Ref,
				Depth:     pkg.Depth,
				Attr: map[string]string{
					"artifact.remote": boolStr(a.Remote),
					"artifact.read":   boolStr(a.Read),
					"hook.package":    pkg.ID,
				},
			})
			setCaps(an, a.Caps)
			if a.Remote {
				g.AddEdge(hookID, artID, graph.EdgeHookFetches)
			} else {
				g.AddEdge(hookID, artID, graph.EdgeHookExecs)
			}
		}

		for _, sk := range h.Sinks {
			sinkID := "sink:" + pkg.ID + "#" + sk.Name
			g.AddNode(&graph.Node{
				ID:        sinkID,
				Kind:      graph.KindSink,
				Ecosystem: pkg.Ecosystem,
				Name:      sk.Name,
				Depth:     pkg.Depth,
				Attr: map[string]string{
					"sink.evidence": sk.Evidence,
					"hook.package":  pkg.ID,
				},
			})
			g.AddEdge(hookID, sinkID, graph.EdgeHookReadsEnv)
		}
	}
}

func sanitize(s string) string {
	return strings.ReplaceAll(s, ":", "_")
}

func setCaps(n *graph.Node, caps []installsurface.Capability) {
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	for _, c := range caps {
		n.Attr["cap."+string(c)] = "true"
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func rootNode(g *graph.Graph, path string) *graph.Node {
	name := filepath.Base(strings.TrimSuffix(filepath.Clean(path), string(filepath.Separator)))
	if name == "." || name == "" || name == composerLockName || name == composerManifestName {
		name = filepath.Base(filepath.Dir(path))
	}
	if name == "." || name == "" {
		name = "php-project"
	}
	id := purl.NewComposer(name, "0.0.0").String()
	n := g.AddNode(&graph.Node{
		ID: id, Ecosystem: "composer", Name: name, Version: "0.0.0", Depth: 0,
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
	for k := range adj {
		sort.Strings(adj[k])
	}
}
