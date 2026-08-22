// Package nuget is the NuGet (.NET) ecosystem adapter. It parses
// packages.lock.json and builds the dependency graph.
//
// Install-time attack vectors:
//   - install.ps1: PowerShell script executed on package install (legacy,
//     packages.config only — PackageReference ignores it)
//   - init.ps1: PowerShell script executed when the solution opens in VS
//   - MSBuild .targets/.props: can run arbitrary targets at build time
//
// Nothing here installs or executes anything (Decision D-04).
package nuget

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// Adapter implements ecosystem.Adapter for NuGet.
type Adapter struct{}

// New returns a NuGet adapter.
func New() *Adapter { return &Adapter{} }

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "nuget" }

const (
	packagesLockName   = "packages.lock.json"
	packagesConfigName = "packages.config"
	paketLockName      = "paket.lock"
)

// Detect implements ecosystem.Adapter. A packages.lock.json (a resolved tree)
// claims the directory; failing that, a packages.config (the legacy .NET
// Framework XML manifest, OPU-15) or a paket.lock (the Paket dependency
// manager's resolved lockfile, OPU-17) claims it too. Both were previously only
// disclosed as unresolvable gaps — paket.lock not even that — never parsed.
func (*Adapter) Detect(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return fileExists(filepath.Join(path, packagesLockName)) ||
			fileExists(filepath.Join(path, packagesConfigName)) ||
			fileExists(filepath.Join(path, paketLockName)) ||
			assetsPath(path) != "" ||
			hasMSBuildSurface(path)
	}
	base := filepath.Base(path)
	if base == packagesLockName || base == packagesConfigName || base == paketLockName ||
		base == directoryPackagesName || base == paketDepsName || base == projectJSONName ||
		base == "dotnet-tools.json" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	return projectExts[ext] || ext == ".nuspec"
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Resolve implements ecosystem.Adapter. A resolved lockfile is preferred:
// packages.lock.json first, then paket.lock (both record exact versions);
// otherwise a packages.config is parsed into its declared package set. A
// directly-pointed file is dispatched by basename.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("nuget: %w", err)
	}
	if !info.IsDir() {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("nuget: reading %s: %w", filepath.Base(path), err)
		}
		switch base := filepath.Base(path); {
		case base == packagesConfigName:
			return parsePackagesConfig(path, raw)
		case base == paketLockName:
			return parsePaketLock(path, raw)
		case base == packagesLockName:
			return parsePackagesLock(path, raw)
		case base == projectAssetsName:
			return parseProjectAssets(filepath.Dir(path), raw)
		default:
			// A directly-pointed modern manifest (.csproj, Directory.Packages.props,
			// .nuspec, dotnet-tools.json, project.json, paket.dependencies) is read
			// in the context of its directory, since Central Package Management and
			// Directory.Build.props live alongside it.
			return parseMSBuildDir(filepath.Dir(path))
		}
	}
	if lock := filepath.Join(path, packagesLockName); fileExists(lock) {
		raw, err := os.ReadFile(lock)
		if err != nil {
			return nil, fmt.Errorf("nuget: reading %s: %w", packagesLockName, err)
		}
		return parsePackagesLock(path, raw)
	}
	if ap := assetsPath(path); ap != "" {
		raw, err := os.ReadFile(ap)
		if err != nil {
			return nil, fmt.Errorf("nuget: reading %s: %w", projectAssetsName, err)
		}
		return parseProjectAssets(path, raw)
	}
	if paket := filepath.Join(path, paketLockName); fileExists(paket) {
		raw, err := os.ReadFile(paket)
		if err != nil {
			return nil, fmt.Errorf("nuget: reading %s: %w", paketLockName, err)
		}
		return parsePaketLock(path, raw)
	}
	// The legacy packages.config still wins when present, but a project may be
	// mid-migration (packages.config alongside PackageReference), so both are
	// read and merged rather than letting either become a blind spot.
	if config := filepath.Join(path, packagesConfigName); fileExists(config) {
		raw, err := os.ReadFile(config)
		if err != nil {
			return nil, fmt.Errorf("nuget: reading %s: %w", packagesConfigName, err)
		}
		g, err := parsePackagesConfig(path, raw)
		if err != nil {
			return nil, err
		}
		if hasMSBuildSurface(path) {
			if mg, mErr := parseMSBuildDir(path); mErr == nil {
				mergeDeclared(g, mg)
			}
		}
		return g, nil
	}
	if hasMSBuildSurface(path) {
		return parseMSBuildDir(path)
	}
	return nil, fmt.Errorf("nuget: no NuGet manifest in %s", filepath.Base(path))
}

// nugetLockFile represents the structure of packages.lock.json.
//
// Format:
//
//	{
//	  "version": 1,
//	  "dependencies": {
//	    "net6.0": {
//	      "PackageName": {
//	        "type": "Direct",
//	        "requested": "[1.0.0, )",
//	        "resolved": "1.0.0",
//	        "dependencies": {
//	          "OtherPkg": "2.0.0"
//	        }
//	      }
//	    }
//	  }
//	}
type nugetLockFile struct {
	Version      int                                     `json:"version"`
	Dependencies map[string]map[string]nugetPackageEntry `json:"dependencies"`
}

type nugetPackageEntry struct {
	Type         string            `json:"type"` // "Direct" or "Transitive"
	Requested    string            `json:"requested"`
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
}

func parsePackagesLock(path string, raw []byte) (*graph.Graph, error) {
	var lf nugetLockFile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("nuget: parsing %s: %w", packagesLockName, err)
	}

	g := graph.New()
	root := rootNode(g, path)

	// Flatten all TFMs (target framework monikers) into one graph. Packages
	// at the same name+version across TFMs are the same node; different
	// versions of the same package are distinct nodes.
	type nameVer struct{ name, version string }
	byNameVer := map[nameVer]string{} // (lowercase name, version) -> node ID

	// Sorted TFM keys for determinism.
	tfms := make([]string, 0, len(lf.Dependencies))
	for tfm := range lf.Dependencies {
		tfms = append(tfms, tfm)
	}
	sort.Strings(tfms)

	for _, tfm := range tfms {
		pkgs := lf.Dependencies[tfm]
		// Sorted package names for determinism.
		names := make([]string, 0, len(pkgs))
		for name := range pkgs {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			entry := pkgs[name]
			if entry.Resolved == "" {
				continue
			}
			lowerName := strings.ToLower(name)
			key := nameVer{lowerName, entry.Resolved}
			if _, exists := byNameVer[key]; exists {
				continue
			}
			id := purl.NewNuGet(name, entry.Resolved).String()
			isDirect := strings.EqualFold(entry.Type, "Direct")
			attr := map[string]string{
				"nuget.source": packagesLockName,
				"nuget.tfm":    tfm,
				"nuget.type":   entry.Type,
			}
			n := g.AddNode(&graph.Node{
				// Name is the lockfile's CANONICAL case. NuGet package ids are
				// case-insensitive for resolution/dedup (keyed on lowerName above,
				// and the PURL folds too), but OSV's NuGet ecosystem is
				// case-SENSITIVE on the name — the OSV coordinate is built straight
				// from n.Name, so lowercasing it here silently missed every advisory
				// and a vulnerable NuGet project scanned green (OPU-14).
				ID: id, Ecosystem: "nuget", Name: name, Version: entry.Resolved,
				Direct: isDirect,
				Attr:   attr,
			})
			// Provenance (D-41). NuGet's lock records the origin in the entry
			// type: "Project" is a sibling project in the solution — local
			// source that nuget.org has never seen — while Direct/Transitive
			// entries came from a feed.
			if strings.EqualFold(entry.Type, "Project") {
				n.SetSource(graph.SourcePath, "")
			} else {
				n.SetSource(graph.SourceRegistry, "")
			}
			byNameVer[key] = id
			if isDirect {
				g.AddEdge(root.ID, id, graph.EdgeDependsOn)
			}
		}
	}

	if g.Len() == 1 {
		return nil, fmt.Errorf("nuget: %s contained no resolved packages", packagesLockName)
	}

	// Per-TFM index: which node was resolved for each package name within
	// each TFM. Used as the deterministic fallback when a dependency value
	// is a version range rather than an exact resolved version.
	tfmNameNode := make(map[string]map[string]string, len(tfms))
	for _, tfm := range tfms {
		idx := make(map[string]string, len(lf.Dependencies[tfm]))
		for name, entry := range lf.Dependencies[tfm] {
			if entry.Resolved == "" {
				continue
			}
			key := nameVer{strings.ToLower(name), entry.Resolved}
			if id, ok := byNameVer[key]; ok {
				idx[strings.ToLower(name)] = id
			}
		}
		tfmNameNode[tfm] = idx
	}

	// Build inter-package edges from dependency maps. A dependency spec in
	// packages.lock.json names only the package and a version; we resolve
	// the target by looking up (lowered dep name, dep version) first, falling
	// back to the version resolved within the SAME TFM when the lock entry
	// carries a range.
	for _, tfm := range tfms {
		pkgs := lf.Dependencies[tfm]
		for name, entry := range pkgs {
			fromKey := nameVer{strings.ToLower(name), entry.Resolved}
			fromID, ok := byNameVer[fromKey]
			if !ok {
				continue
			}
			for dep, depVer := range entry.Dependencies {
				lowerDep := strings.ToLower(dep)
				toID, ok := byNameVer[nameVer{lowerDep, depVer}]
				if !ok {
					toID, ok = tfmNameNode[tfm][lowerDep]
				}
				if !ok || toID == fromID {
					continue
				}
				g.AddEdge(fromID, toID, graph.EdgeDependsOn)
			}
		}
	}

	// Transitive packages with no inbound from another package hang off root.
	hasInbound := map[string]bool{}
	for _, e := range g.SortedEdges() {
		if e.From != root.ID && e.Type == graph.EdgeDependsOn {
			hasInbound[e.To] = true
		}
	}
	for _, id := range byNameVer {
		if !hasInbound[id] {
			n := g.Get(id)
			if n != nil && !n.Direct {
				g.AddEdge(root.ID, id, graph.EdgeDependsOn)
				n.Direct = true
			}
		}
	}

	assignDepths(g, root.ID)
	return g, nil
}

// packagesConfig is the legacy NuGet packages.config XML: a flat list of
// resolved packages with no dependency graph.
//
//	<packages>
//	  <package id="Newtonsoft.Json" version="12.0.3" targetFramework="net472" />
//	</packages>
type packagesConfig struct {
	XMLName  xml.Name `xml:"packages"`
	Packages []struct {
		ID              string `xml:"id,attr"`
		Version         string `xml:"version,attr"`
		TargetFramework string `xml:"targetFramework,attr"`
	} `xml:"package"`
}

// parsePackagesConfig parses a packages.config into direct NuGet package nodes.
// The file is a FLAT list — both direct and transitive packages appear with no
// edges — so every entry becomes a direct dependency of the root. Names are kept
// in canonical case for the case-sensitive OSV coordinate (OPU-14); a leading
// UTF-8 BOM (common on Windows-authored configs) is stripped first.
func parsePackagesConfig(path string, raw []byte) (*graph.Graph, error) {
	raw = bytes.TrimPrefix(raw, []byte("\uFEFF"))
	var cfg packagesConfig
	if err := xml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("nuget: parsing %s: %w", packagesConfigName, err)
	}

	g := graph.New()
	root := rootNode(g, path)
	seen := map[string]bool{}
	for _, p := range cfg.Packages {
		if p.ID == "" || p.Version == "" {
			continue
		}
		id := purl.NewNuGet(p.ID, p.Version).String()
		if seen[id] {
			continue
		}
		seen[id] = true
		attr := map[string]string{"nuget.source": packagesConfigName}
		if p.TargetFramework != "" {
			attr["nuget.tfm"] = p.TargetFramework
		}
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "nuget", Name: p.ID, Version: p.Version,
			Direct: true, Depth: 1, Attr: attr,
		})
		n.SetSource(graph.SourceRegistry, "")
		g.AddEdge(root.ID, id, graph.EdgeDependsOn)
	}
	if g.Len() == 1 {
		return nil, fmt.Errorf("nuget: %s contained no packages", packagesConfigName)
	}
	assignDepths(g, root.ID)
	return g, nil
}

// parsePaketLock parses a Paket paket.lock — the resolved lockfile of the Paket
// .NET dependency manager. Paket packages ARE NuGet packages (same registry,
// same pkg:nuget/ coordinate, same case-sensitive OSV ecosystem), so they become
// ordinary nuget nodes. Only NUGET-group entries are read; GITHUB/GIT/HTTP
// sections point at non-NuGet sources and are skipped. A Paket project was
// previously SILENTLY skipped — not even disclosed — with no signal at all
// (OPU-17).
//
// Format (groups optional; the default group is unnamed):
//
//	NUGET
//	  remote: https://api.nuget.org/v3/index.json
//	    Newtonsoft.Json (12.0.3)
//	      System.Runtime (>= 4.3)
//	    System.Net.Http (4.3.0)
//
//	GROUP Build
//	NUGET
//	  remote: https://api.nuget.org/v3/index.json
//	    FAKE (5.0.0)
func parsePaketLock(path string, raw []byte) (*graph.Graph, error) {
	g := graph.New()
	root := rootNode(g, path)

	type paketPkg struct {
		name, version string
		deps          []string
	}
	var (
		pkgs    []paketPkg
		section string
		curPkg  *paketPkg
	)

	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Section/group headers are unindented.
		if line[0] != ' ' && line[0] != '\t' {
			trimmed := strings.TrimSpace(line)
			if rest, ok := strings.CutPrefix(trimmed, "GROUP"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
				// A new group resets the section; its packages are still NuGet.
				section = ""
			} else {
				section = strings.ToUpper(strings.Fields(trimmed)[0])
			}
			curPkg = nil
			continue
		}
		if section != "NUGET" {
			continue
		}
		indent := countIndent(line)
		trimmed := strings.TrimSpace(line)
		switch {
		case indent <= 2:
			// remote: / framework restrictions / options — preamble, not a package.
			curPkg = nil
		case indent <= 4:
			name, version := parsePaketSpec(trimmed)
			if name != "" && version != "" {
				pkgs = append(pkgs, paketPkg{name: name, version: version})
				curPkg = &pkgs[len(pkgs)-1]
			} else {
				curPkg = nil
			}
		default: // indent >= 6: a dependency of the current package
			if curPkg != nil {
				if dep, _ := parsePaketSpec(trimmed); dep != "" {
					curPkg.deps = append(curPkg.deps, dep)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nuget: scanning %s: %w", paketLockName, err)
	}

	// Build nodes (canonical case — the OSV coordinate is case-sensitive, D-62),
	// deduped by PURL id so the same package pinned in several groups is one node.
	byLowerName := map[string]string{} // lower(name) -> node ID (for edge lookup)
	seen := map[string]bool{}
	for _, p := range pkgs {
		id := purl.NewNuGet(p.name, p.version).String()
		if seen[id] {
			continue
		}
		seen[id] = true
		n := g.AddNode(&graph.Node{
			ID: id, Ecosystem: "nuget", Name: p.name, Version: p.version,
			Attr: map[string]string{"nuget.source": paketLockName},
		})
		n.SetSource(graph.SourceRegistry, "")
		byLowerName[strings.ToLower(p.name)] = id
	}
	if g.Len() == 1 {
		return nil, fmt.Errorf("nuget: %s contained no NUGET packages", paketLockName)
	}

	// Inter-package edges (NuGet ids are case-insensitive, so fold for lookup).
	for _, p := range pkgs {
		fromID, ok := byLowerName[strings.ToLower(p.name)]
		if !ok {
			continue
		}
		for _, dep := range p.deps {
			toID, ok := byLowerName[strings.ToLower(dep)]
			if !ok || toID == fromID {
				continue
			}
			g.AddEdge(fromID, toID, graph.EdgeDependsOn)
		}
	}

	// Any package with no inbound edge from another package hangs off root.
	hasInbound := map[string]bool{}
	for _, e := range g.SortedEdges() {
		if e.From != root.ID && e.Type == graph.EdgeDependsOn {
			hasInbound[e.To] = true
		}
	}
	for _, id := range byLowerName {
		if !hasInbound[id] {
			g.AddEdge(root.ID, id, graph.EdgeDependsOn)
			if n := g.Get(id); n != nil {
				n.Direct = true
			}
		}
	}

	assignDepths(g, root.ID)
	return g, nil
}

// parsePaketSpec splits a paket.lock entry "Name (version) - restriction: ..."
// into name and the version between the first parentheses. A dependency line
// "Name (>= 4.3)" yields the name and a constraint (ignored by the caller).
func parsePaketSpec(s string) (name, version string) {
	open := strings.IndexByte(s, '(')
	if open < 0 {
		return strings.TrimSpace(s), ""
	}
	name = strings.TrimSpace(s[:open])
	rest := s[open+1:]
	if end := strings.IndexByte(rest, ')'); end >= 0 {
		version = strings.TrimSpace(rest[:end])
	}
	return name, version
}

// countIndent counts leading spaces (paket.lock indents with spaces).
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
	if name == "." || name == "" || name == packagesLockName || name == packagesConfigName || name == paketLockName {
		name = filepath.Base(filepath.Dir(path))
	}
	if name == "." || name == "" {
		name = "dotnet-project"
	}
	id := purl.NewNuGet(name, "0.0.0").String()
	n := g.AddNode(&graph.Node{
		ID: id, Ecosystem: "nuget", Name: strings.ToLower(name), Version: "0.0.0", Depth: 0,
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
