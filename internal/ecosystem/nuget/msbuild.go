package nuget

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// This file covers the MODERN .NET dependency surface. Before it, the adapter
// read packages.lock.json, paket.lock and packages.config only — so any project
// using PackageReference (the SDK-style default since VS2017/.NET Core) resolved
// to ZERO packages and was disclosed as a recognized-but-unresolved manifest.
// That is the majority of .NET repositories today.
//
// Declared-manifest formats read here (all FLAT — declared, not locked, D-24):
//
//   - <PackageReference> in .csproj / .vbproj / .fsproj / .vcxproj / .proj
//   - Central Package Management: Directory.Packages.props <PackageVersion> and
//     <GlobalPackageReference> (a versionless PackageReference gets its version
//     from there)
//   - Directory.Build.props / Directory.Build.targets (PackageReference and
//     MSBuild properties inherited by every project in the tree)
//   - .nuspec <dependency> (package authoring manifests)
//   - .config/dotnet-tools.json (local tool manifest — these tools EXECUTE)
//   - project.json (pre-VS2017 .NET Core)
//   - paket.dependencies (Paket manifest, when no paket.lock is present)
//
// Nothing here installs, restores, or executes anything (D-04). Versions that
// cannot be determined statically (unexpandable $(Property), floating/range
// versions) are DISCLOSED as unresolved rather than guessed or dropped (D-59).

var (
	projectExts = map[string]bool{
		".csproj": true, ".vbproj": true, ".fsproj": true, ".vcxproj": true, ".proj": true,
	}
	directoryPackagesName = "Directory.Packages.props"
	dotnetToolsRelPath    = filepath.Join(".config", "dotnet-tools.json")
	paketDepsName         = "paket.dependencies"
	projectJSONName       = "project.json"

	// msbuildPropRe matches an MSBuild property reference such as $(SerilogVersion).
	msbuildPropRe = regexp.MustCompile(`\$\(([A-Za-z_][A-Za-z0-9_.-]*)\)`)
	// paketNugetRe matches a paket.dependencies nuget line: `nuget Name 1.2.3`.
	paketNugetRe = regexp.MustCompile(`^\s*nuget\s+(\S+)(?:\s+([^\s]+))?`)
)

// msbuildFile is the subset of an MSBuild XML file this adapter reads. Version
// may be an attribute or a child element, and both spellings are accepted.
type msbuildFile struct {
	PropertyGroups []struct {
		Props []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"PropertyGroup"`
	ItemGroups []struct {
		PackageReference       []msbuildItem `xml:"PackageReference"`
		PackageVersion         []msbuildItem `xml:"PackageVersion"`
		GlobalPackageReference []msbuildItem `xml:"GlobalPackageReference"`
	} `xml:"ItemGroup"`
}

type msbuildItem struct {
	Include     string `xml:"Include,attr"`
	Update      string `xml:"Update,attr"`
	VersionAttr string `xml:"Version,attr"`
	VersionElem string `xml:"Version"`
}

func (i msbuildItem) name() string {
	if i.Include != "" {
		return strings.TrimSpace(i.Include)
	}
	return strings.TrimSpace(i.Update)
}

func (i msbuildItem) version() string {
	if v := strings.TrimSpace(i.VersionAttr); v != "" {
		return v
	}
	return strings.TrimSpace(i.VersionElem)
}

// nuspecFile is the .nuspec package authoring manifest.
type nuspecFile struct {
	Metadata struct {
		Dependencies struct {
			Dependency []struct {
				ID      string `xml:"id,attr"`
				Version string `xml:"version,attr"`
			} `xml:"dependency"`
			Group []struct {
				Dependency []struct {
					ID      string `xml:"id,attr"`
					Version string `xml:"version,attr"`
				} `xml:"dependency"`
			} `xml:"group"`
		} `xml:"dependencies"`
	} `xml:"metadata"`
}

type dotnetTools struct {
	Tools map[string]struct {
		Version string `json:"version"`
	} `json:"tools"`
}

type legacyProjectJSON struct {
	Dependencies map[string]json.RawMessage `json:"dependencies"`
}

// declaredPkg is one declared dependency plus where it was declared.
type declaredPkg struct {
	name    string
	version string
	source  string
}

// msbuildScan is the accumulated result of reading a directory's .NET manifests.
type msbuildScan struct {
	pkgs       []declaredPkg
	unresolved []string // "name (reason)" — disclosed, never silently dropped
	sources    map[string]bool
}

// hasMSBuildSurface reports whether dir contains any modern .NET manifest this
// file can read.
func hasMSBuildSurface(dir string) bool {
	if fileExists(filepath.Join(dir, directoryPackagesName)) ||
		fileExists(filepath.Join(dir, "Directory.Build.props")) ||
		fileExists(filepath.Join(dir, "Directory.Build.targets")) ||
		fileExists(filepath.Join(dir, dotnetToolsRelPath)) ||
		fileExists(filepath.Join(dir, paketDepsName)) ||
		fileExists(filepath.Join(dir, projectJSONName)) {
		return true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if projectExts[ext] || ext == ".nuspec" {
			return true
		}
	}
	return false
}

// parseMSBuildDir reads every modern .NET manifest in dir and merges them into
// one flat declared graph.
func parseMSBuildDir(dir string) (*graph.Graph, error) {
	scan := &msbuildScan{sources: map[string]bool{}}

	// MSBuild properties usable for $(Version) expansion, plus the Central
	// Package Management version table. Directory.Build.props and
	// Directory.Packages.props apply to every project in the tree, so they are
	// read first.
	props := map[string]string{}
	cpm := map[string]string{}
	// MSBuild discovers Directory.Packages.props / Directory.Build.props by
	// walking UP the directory tree, so a repo-root Central Package Management
	// file governs projects nested in src/*. Reading only the project's own
	// directory would leave every versionless PackageReference unresolvable —
	// which is precisely how Polly (59 PackageVersion entries at the repo root)
	// resolved to zero packages. Ancestors are read outermost-first so the
	// NEAREST definition wins.
	for _, ancestor := range ancestorDirs(dir) {
		for _, shared := range []string{directoryPackagesName, "Directory.Build.props", "Directory.Build.targets"} {
			p := filepath.Join(ancestor, shared)
			if !fileExists(p) {
				continue
			}
			if raw, err := os.ReadFile(p); err == nil {
				scan.readMSBuild(raw, shared, props, cpm, true)
			}
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("nuget: reading %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // determinism (D-13)

	for _, name := range names {
		ext := strings.ToLower(filepath.Ext(name))
		full := filepath.Join(dir, name)
		switch {
		case projectExts[ext]:
			if raw, err := os.ReadFile(full); err == nil {
				scan.readMSBuild(raw, name, props, cpm, false)
			}
		case ext == ".nuspec":
			if raw, err := os.ReadFile(full); err == nil {
				scan.readNuspec(raw, name, props)
			}
		case name == projectJSONName:
			if raw, err := os.ReadFile(full); err == nil {
				scan.readProjectJSON(raw, name)
			}
		case name == paketDepsName && !fileExists(filepath.Join(dir, paketLockName)):
			// The resolved paket.lock always wins when present.
			if raw, err := os.ReadFile(full); err == nil {
				scan.readPaketDeps(raw, name)
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, dotnetToolsRelPath)); err == nil {
		scan.readDotnetTools(raw, "dotnet-tools.json")
	}

	// A project that declares no packages (only ProjectReferences, say) is a
	// legitimate zero-dependency project, not a failed parse — reporting it as a
	// failure would turn ordinary repos into false "failed project" noise.
	return scan.build(dir)
}

// readMSBuild reads PackageReference / PackageVersion / GlobalPackageReference
// items and PropertyGroup properties. shared marks Directory.* files, whose
// PackageVersion entries populate the Central Package Management table.
func (s *msbuildScan) readMSBuild(raw []byte, source string, props, cpm map[string]string, shared bool) {
	raw = bytes.TrimPrefix(raw, []byte("\uFEFF"))
	var f msbuildFile
	if xml.Unmarshal(raw, &f) != nil {
		return // unparseable MSBuild XML: nothing claimed from it
	}
	for _, pg := range f.PropertyGroups {
		for _, p := range pg.Props {
			if v := strings.TrimSpace(p.Value); v != "" {
				props[p.XMLName.Local] = v
			}
		}
	}
	for _, ig := range f.ItemGroups {
		// Central Package Management version table.
		for _, pv := range ig.PackageVersion {
			if n, v := pv.name(), pv.version(); n != "" && v != "" {
				cpm[strings.ToLower(n)] = v
			}
		}
		// GlobalPackageReference is a real dependency applied to all projects.
		for _, gr := range ig.GlobalPackageReference {
			s.add(gr.name(), gr.version(), source, props, cpm)
		}
		for _, pr := range ig.PackageReference {
			s.add(pr.name(), pr.version(), source, props, cpm)
		}
	}
	_ = shared
}

func (s *msbuildScan) readNuspec(raw []byte, source string, props map[string]string) {
	raw = bytes.TrimPrefix(raw, []byte("\uFEFF"))
	var f nuspecFile
	if xml.Unmarshal(raw, &f) != nil {
		return
	}
	deps := f.Metadata.Dependencies.Dependency
	for _, g := range f.Metadata.Dependencies.Group {
		deps = append(deps, g.Dependency...)
	}
	for _, d := range deps {
		s.add(d.ID, d.Version, source, props, nil)
	}
}

func (s *msbuildScan) readDotnetTools(raw []byte, source string) {
	var f dotnetTools
	if json.Unmarshal(raw, &f) != nil {
		return
	}
	names := make([]string, 0, len(f.Tools))
	for n := range f.Tools {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s.add(n, f.Tools[n].Version, source, nil, nil)
	}
}

func (s *msbuildScan) readProjectJSON(raw []byte, source string) {
	var f legacyProjectJSON
	if json.Unmarshal(raw, &f) != nil {
		return
	}
	names := make([]string, 0, len(f.Dependencies))
	for n := range f.Dependencies {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		var ver string
		if json.Unmarshal(f.Dependencies[n], &ver) != nil {
			// object form: {"version":"1.2.3","type":"build"}
			var obj struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(f.Dependencies[n], &obj) == nil {
				ver = obj.Version
			}
		}
		s.add(n, ver, source, nil, nil)
	}
}

func (s *msbuildScan) readPaketDeps(raw []byte, source string) {
	for _, line := range strings.Split(string(raw), "\n") {
		m := paketNugetRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s.add(m[1], m[2], source, nil, nil)
	}
}

// add records one declared dependency, resolving its version through MSBuild
// property expansion and the Central Package Management table. Anything that
// cannot be pinned to a concrete version is disclosed as unresolved (D-59).
func (s *msbuildScan) add(name, version, source string, props, cpm map[string]string) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "$@*") {
		return // an MSBuild glob/property item, not a package id
	}
	s.sources[source] = true

	version = strings.TrimSpace(version)
	if version == "" && cpm != nil {
		version = cpm[strings.ToLower(name)] // Central Package Management
	}
	if version != "" && props != nil {
		version = expandProps(version, props)
	}
	concrete, ok := concreteVersion(version)
	if !ok {
		reason := "no version"
		switch {
		case version == "":
			reason = "no version (and no Directory.Packages.props entry)"
		case msbuildPropRe.MatchString(version):
			reason = "unexpandable " + version
		default:
			reason = "floating/range version " + version
		}
		s.unresolved = append(s.unresolved, name+" ["+reason+"]")
		return
	}
	s.pkgs = append(s.pkgs, declaredPkg{name: name, version: concrete, source: source})
}

// expandProps substitutes $(Prop) references from the collected MSBuild
// properties, one level deep (enough for the near-universal
// `Version="$(SomePackageVersion)"` idiom).
func expandProps(v string, props map[string]string) string {
	return msbuildPropRe.ReplaceAllStringFunc(v, func(m string) string {
		key := msbuildPropRe.FindStringSubmatch(m)[1]
		if val, ok := props[key]; ok {
			return val
		}
		return m // left as-is; reported as unexpandable
	})
}

// concreteVersion accepts an exact NuGet version, including the bracketed exact
// pin `[1.2.3]`. Floating (`1.2.*`), open ranges (`[1.0,2.0)`) and unexpanded
// properties are NOT concrete: OSV needs an exact coordinate, and inventing one
// would be a false-clean.
func concreteVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") && !strings.Contains(v, ",") {
		v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	}
	if v == "" || strings.ContainsAny(v, "$*,()[]") {
		return "", false
	}
	return v, true
}

// build turns the accumulated declarations into a flat graph: every declared
// package is a direct dependency of the root, since none of these formats
// records a resolved transitive tree (D-24).
func (s *msbuildScan) build(dir string) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, dir)
	seen := map[string]bool{}
	for _, p := range s.pkgs {
		id := purl.NewNuGet(p.name, p.version).String()
		if seen[id] {
			continue
		}
		seen[id] = true
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "nuget", Name: p.name, Version: p.version,
			Direct: true, Depth: 1,
			Attr: map[string]string{"nuget.source": p.source},
		})
		n.SetSource(graph.SourceRegistry, "")
		g.AddEdge(root.ID, id, graph.EdgeDependsOn)
	}
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}
	// These formats declare dependencies; they do not lock a transitive tree.
	// Disclosed, not faked (D-24).
	root.Attr[graph.AttrFlatResolution] = "nuget"
	if len(s.unresolved) > 0 {
		sort.Strings(s.unresolved)
		root.Attr[graph.AttrUnresolved] = strings.Join(s.unresolved, ",")
		root.Attr[graph.AttrUnresolvedCount] = strconv.Itoa(len(s.unresolved))
	}
	if len(s.sources) > 0 {
		srcs := make([]string, 0, len(s.sources))
		for k := range s.sources {
			srcs = append(srcs, k)
		}
		sort.Strings(srcs)
		root.Attr["nuget.declared_from"] = strings.Join(srcs, ",")
	}
	assignDepths(g, root.ID)
	return g, nil
}

// mergeDeclared folds the declared-manifest graph src into dst (a packages.config
// graph), so a project mid-migration between packages.config and PackageReference
// is covered by both rather than only the legacy half.
func mergeDeclared(dst, src *graph.Graph) {
	var dstRoot string
	for _, r := range dst.Roots {
		dstRoot = r
		break
	}
	if dstRoot == "" {
		return
	}
	for _, n := range src.SortedNodes() {
		if n.Ecosystem != "nuget" || n.Version == "" {
			continue
		}
		if existing := dst.Get(n.ID); existing != nil {
			continue
		}
		copyNode := *n
		added := dst.AddNode(&copyNode)
		added.SetSource(graph.SourceRegistry, "")
		dst.AddEdge(dstRoot, added.ID, graph.EdgeDependsOn)
	}
	if root := dst.Get(dstRoot); root != nil {
		if root.Attr == nil {
			root.Attr = map[string]string{}
		}
		if srcRootID := firstRoot(src); srcRootID != "" {
			if sr := src.Get(srcRootID); sr != nil {
				for _, k := range []string{graph.AttrUnresolved, graph.AttrUnresolvedCount, "nuget.declared_from"} {
					if v, ok := sr.Attr[k]; ok && v != "" {
						root.Attr[k] = v
					}
				}
			}
		}
		root.Attr[graph.AttrFlatResolution] = "nuget"
	}
}

func firstRoot(g *graph.Graph) string {
	for _, r := range g.Roots {
		return r
	}
	return ""
}

const projectAssetsName = "project.assets.json"

// projectAssets is the NuGet restore output (obj/project.assets.json). Unlike
// every other declared format it records the RESOLVED transitive tree — package
// -> package edges included — so when present it is preferred over
// PackageReference and is NOT flat.
type projectAssets struct {
	Targets map[string]map[string]struct {
		Type         string            `json:"type"`
		Dependencies map[string]string `json:"dependencies"`
	} `json:"targets"`
}

// assetsPath returns the project.assets.json for dir (either alongside it or in
// the conventional obj/ subdirectory), or "".
func assetsPath(dir string) string {
	// A bare obj/ directory is NOT its own project: its parent owns the restore
	// output, so claiming it here would produce a duplicate root.
	if strings.EqualFold(filepath.Base(dir), "obj") {
		return ""
	}
	for _, p := range []string{
		filepath.Join(dir, projectAssetsName),
		filepath.Join(dir, "obj", projectAssetsName),
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// parseProjectAssets builds a graph with real transitive edges from a restore's
// project.assets.json. Only "package" entries are used; "project" entries are
// local project references, not NuGet packages.
func parseProjectAssets(dir string, raw []byte) (*graph.Graph, error) {
	var a projectAssets
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("nuget: parsing %s: %w", projectAssetsName, err)
	}
	g := graph.New()
	root := rootNode(g, dir)

	// Deterministic target framework choice (D-13): a lockfile can carry several.
	tfms := make([]string, 0, len(a.Targets))
	for t := range a.Targets {
		tfms = append(tfms, t)
	}
	sort.Strings(tfms)

	idOf := func(spec string) (id, name, ver string, ok bool) {
		i := strings.LastIndex(spec, "/")
		if i <= 0 || i == len(spec)-1 {
			return "", "", "", false
		}
		name, ver = spec[:i], spec[i+1:]
		return purl.NewNuGet(name, ver).String(), name, ver, true
	}

	seen := map[string]bool{}
	for _, tfm := range tfms {
		libs := a.Targets[tfm]
		specs := make([]string, 0, len(libs))
		for s := range libs {
			specs = append(specs, s)
		}
		sort.Strings(specs)
		for _, spec := range specs {
			lib := libs[spec]
			if !strings.EqualFold(lib.Type, "package") {
				continue
			}
			id, name, ver, ok := idOf(spec)
			if !ok || seen[id] {
				continue
			}
			seen[id] = true
			n := g.AddNode(&graph.Node{
				ID: id, Ecosystem: "nuget", Name: name, Version: ver,
				Attr: map[string]string{"nuget.source": projectAssetsName, "nuget.tfm": tfm},
			})
			n.SetSource(graph.SourceRegistry, "")
		}
		// Edges: a package's own dependencies, resolved against this target.
		for _, spec := range specs {
			lib := libs[spec]
			if !strings.EqualFold(lib.Type, "package") {
				continue
			}
			fromID, _, _, ok := idOf(spec)
			if !ok {
				continue
			}
			depNames := make([]string, 0, len(lib.Dependencies))
			for d := range lib.Dependencies {
				depNames = append(depNames, d)
			}
			sort.Strings(depNames)
			for _, d := range depNames {
				toID := purl.NewNuGet(d, lib.Dependencies[d]).String()
				if g.Get(toID) != nil {
					g.AddEdge(fromID, toID, graph.EdgeDependsOn)
				}
			}
		}
	}
	if g.Len() == 1 {
		return nil, fmt.Errorf("nuget: %s contained no packages", projectAssetsName)
	}
	// Anything with no incoming package edge is a direct dependency of the root.
	hasParent := map[string]bool{}
	for _, e := range g.SortedEdges() {
		if e.From != root.ID {
			hasParent[e.To] = true
		}
	}
	for _, n := range g.SortedNodes() {
		if n.ID != root.ID && !hasParent[n.ID] {
			n.Direct = true
			g.AddEdge(root.ID, n.ID, graph.EdgeDependsOn)
		}
	}
	assignDepths(g, root.ID)
	return g, nil
}

// ancestorDirs returns dir and its ancestors, OUTERMOST FIRST, stopping at the
// repository root (a directory containing .git) or the filesystem root. The
// depth cap is a guard against pathological paths, not a semantic limit.
func ancestorDirs(dir string) []string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return []string{dir}
	}
	var chain []string
	for i := 0; i < 32; i++ {
		chain = append(chain, abs)
		if fileExists(filepath.Join(abs, ".git")) || dirExists(filepath.Join(abs, ".git")) {
			break // repository root: do not read outside the scanned tree
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	// reverse: outermost first, so nearer definitions overwrite farther ones
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
