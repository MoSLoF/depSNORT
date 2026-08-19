// Package gomod is the Go module ecosystem adapter. It reads go.mod's resolved
// require set — the exact versions Go's minimal-version-selection already
// pinned — with no execution (Decision D-04: `go` is never run).
//
// # What go.mod records
//
// A go.mod `require` block lists every module in the build, direct and (marked
// "// indirect") transitive, each at an EXACT version. That is a fully-pinned,
// FLAT set: unlike package-lock.json, go.mod records no inter-module edges (who
// requires whom). So every module resolves as an observed node, and the tree
// beneath the root is one layer deep by construction — the same flat-resolution
// fact a pinned requirements.txt or Pipfile.lock carries (D-24). Transitive
// expansion (D-44) can rebuild the real edges from each module's own go.mod.
//
// go.sum is a hash ledger, not a dependency list — it verifies module content
// and is not parsed for structure here.
package gomod

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

const goModName = "go.mod"

// Adapter implements ecosystem.Adapter for Go modules.
type Adapter struct{}

// New returns a Go module adapter.
func New() *Adapter { return &Adapter{} }

// Name implements ecosystem.Adapter.
func (*Adapter) Name() string { return "gomod" }

func modPath(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		p := filepath.Join(path, goModName)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	if filepath.Base(path) == goModName {
		return path
	}
	return ""
}

// Detect implements ecosystem.Adapter.
func (*Adapter) Detect(path string) bool { return modPath(path) != "" }

// Resolve implements ecosystem.Adapter.
func (*Adapter) Resolve(path string) (*graph.Graph, error) {
	mp := modPath(path)
	if mp == "" {
		return nil, fmt.Errorf("gomod: no %s found at %q", goModName, path)
	}
	raw, err := os.ReadFile(mp)
	if err != nil {
		return nil, fmt.Errorf("gomod: reading %s: %w", mp, err)
	}
	return parseGoMod(mp, raw)
}

type require struct {
	module   string
	version  string
	indirect bool
}

func parseGoMod(path string, raw []byte) (*graph.Graph, error) {
	modName, requires := scanGoMod(raw)
	if modName == "" {
		modName = filepath.Base(filepath.Dir(path))
	}

	g := graph.New()
	rootID := purl.NewGo(modName, "0.0.0").String()
	root := g.AddNode(&graph.Node{
		ID: rootID, Ecosystem: "gomod", Name: modName, Version: "0.0.0", Depth: 0,
		// The module's own version is not in go.mod (it comes from a VCS tag);
		// 0.0.0 is the placeholder, tagged so a reader can tell it apart from a
		// genuine 0.0.0.
		Attr: map[string]string{"gomod.version_source": "unresolved-placeholder", "gomod.source": goModName},
	})
	g.MarkRoot(rootID)
	if root.Attr == nil {
		root.Attr = map[string]string{}
	}

	if len(requires) == 0 {
		return g, nil
	}

	for _, r := range requires {
		id := purl.NewGo(r.module, r.version).String()
		g.AddNode(&graph.Node{
			ID: id, Ecosystem: "gomod", Name: r.module, Version: r.version, Depth: 1,
			Direct: !r.indirect,
			Attr:   map[string]string{"gomod.source": goModName},
		})
		// go.mod records no edges; every require hangs off the root. Direct vs
		// indirect is a FACT go.mod states (the "// indirect" marker), recorded
		// on the node but not turned into a real transitive edge that go.mod
		// does not actually record.
		g.AddEdge(rootID, id, graph.EdgeDependsOn)
	}

	// go.mod is a flat resolution (no inter-module edges), so disclose it the
	// way every other flat format is (D-24); expansion can rebuild the edges.
	root.Attr[graph.AttrFlatResolution] = "gomod"
	return g, nil
}

// scanGoMod extracts the module path and the require set. It handles both the
// block form `require ( ... )` and single-line `require mod v1.2.3`, and the
// "// indirect" marker. `replace`, `exclude`, and `retract` directives are
// ignored — they are policy, not the resolved set, and this adapter reads what
// go.mod pins.
func scanGoMod(raw []byte) (module string, requires []require) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inRequireBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "//"); i >= 0 && !strings.Contains(line[:i], "indirect") {
			// Strip a trailing comment that is not the indirect marker; keep the
			// marker itself for detection below.
			if !strings.Contains(line, "// indirect") {
				line = strings.TrimSpace(line[:i])
			}
		}
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "module "):
			module = strings.TrimSpace(strings.TrimPrefix(line, "module "))
		case line == "require (":
			inRequireBlock = true
		case inRequireBlock && line == ")":
			inRequireBlock = false
		case inRequireBlock:
			if r, ok := parseRequireLine(line); ok {
				requires = append(requires, r)
			}
		case strings.HasPrefix(line, "require "):
			if r, ok := parseRequireLine(strings.TrimPrefix(line, "require ")); ok {
				requires = append(requires, r)
			}
		}
	}
	sort.Slice(requires, func(i, j int) bool { return requires[i].module < requires[j].module })
	return module, requires
}

// parseRequireLine reads "module vX.Y.Z" or "module vX.Y.Z // indirect".
func parseRequireLine(line string) (require, bool) {
	indirect := strings.Contains(line, "// indirect")
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return require{}, false
	}
	mod, ver := fields[0], fields[1]
	if mod == "" || !strings.HasPrefix(ver, "v") {
		return require{}, false
	}
	return require{module: mod, version: ver, indirect: indirect}, true
}
