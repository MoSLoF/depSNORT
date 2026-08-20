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
	"strconv"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

const goModName = "go.mod"

// AttrGoDirective is the root-node attribute holding a Go main module's `go`
// directive (e.g. "1.25"), set by the adapter and read by the report layer to
// decide the module-graph-pruning disclosure (OPU-15).
const AttrGoDirective = "gomod.go"

// HasPrunedModuleGraph reports whether a main module's `go` directive triggers
// Go 1.17+ module-graph pruning. depsnort resolves the UNPRUNED graph, so such a
// module's Go closure is a deliberate over-approximation, disclosed in the report
// until static pruning lands (OPU-15).
func HasPrunedModuleGraph(goDirective string) bool { return goDirectiveAtLeast(goDirective, 1, 17) }

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
	// Record the `go` directive: a go 1.17+ main module has a PRUNED module graph,
	// so its expanded closure is a deliberate over-approximation, disclosed at the
	// report level (OPU-15) until static pruning lands.
	if gd := goDirective(raw); gd != "" {
		root.Attr[AttrGoDirective] = gd
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

// goDirective returns the `go` directive version of a go.mod (e.g. "1.25"), or
// "" if absent. It is the switch for module-graph pruning: Go 1.17+ prunes the
// graph, so a go 1.17+ main module's resolved closure is a deliberate
// over-approximation until static pruning lands (OPU-15).
func goDirective(raw []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "go "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// goDirectiveAtLeast reports whether a `go` directive string (e.g. "1.25",
// "1.21.0") is >= major.minor. Malformed or absent directives report false, so a
// module of unknown vintage is treated as pre-1.17 (the conservative, unpruned
// path — never wrongly prune).
func goDirectiveAtLeast(directive string, major, minor int) bool {
	directive = strings.TrimSpace(directive)
	if directive == "" {
		return false
	}
	parts := strings.SplitN(directive, ".", 3)
	if len(parts) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > major || (maj == major && min >= minor)
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
