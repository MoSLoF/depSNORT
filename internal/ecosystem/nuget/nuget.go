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
	"encoding/json"
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

const packagesLockName = "packages.lock.json"

// Detect implements ecosystem.Adapter.
func (*Adapter) Detect(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return fileExists(filepath.Join(path, packagesLockName))
	}
	return filepath.Base(path) == packagesLockName
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// Resolve implements ecosystem.Adapter.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	file := path
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("nuget: %w", err)
	}
	if info.IsDir() {
		file = filepath.Join(path, packagesLockName)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("nuget: reading %s: %w", packagesLockName, err)
	}
	return parsePackagesLock(path, raw)
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
	Version      int                                       `json:"version"`
	Dependencies map[string]map[string]nugetPackageEntry   `json:"dependencies"`
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
	// at the same version across TFMs are the same node.
	byName := map[string]string{} // lowercase name -> node ID

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
			if _, exists := byName[lowerName]; exists {
				continue
			}
			id := purl.NewNuGet(name, entry.Resolved).String()
			isDirect := strings.EqualFold(entry.Type, "Direct")
			attr := map[string]string{
				"nuget.source": packagesLockName,
				"nuget.tfm":    tfm,
				"nuget.type":   entry.Type,
			}
			g.AddNode(&graph.Node{
				ID: id, Ecosystem: "nuget", Name: lowerName, Version: entry.Resolved,
				Direct: isDirect,
				Attr:   attr,
			})
			byName[lowerName] = id
			if isDirect {
				g.AddEdge(root.ID, id, graph.EdgeDependsOn)
			}
		}
	}

	if g.Len() == 1 {
		return nil, fmt.Errorf("nuget: %s contained no resolved packages", packagesLockName)
	}

	// Build inter-package edges from dependency maps.
	for _, tfm := range tfms {
		pkgs := lf.Dependencies[tfm]
		for name, entry := range pkgs {
			fromID, ok := byName[strings.ToLower(name)]
			if !ok {
				continue
			}
			for dep := range entry.Dependencies {
				toID, ok := byName[strings.ToLower(dep)]
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
	for name, id := range byName {
		_ = name
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

func rootNode(g *graph.Graph, path string) *graph.Node {
	name := filepath.Base(strings.TrimSuffix(filepath.Clean(path), string(filepath.Separator)))
	if name == "." || name == "" || name == packagesLockName {
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
