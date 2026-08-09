package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// pkgManifest is the subset of a package's own package.json we read.
type pkgManifest struct {
	Scripts map[string]string `json:"scripts"`
}

// rootDir resolves the project root from a path that may be a dir or the
// lockfile itself.
func rootDir(path string) string {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return filepath.Dir(path)
	}
	return path
}

// ExtractInstallSurface implements ecosystem.InstallSurfaceExtractor.
//
// It reads each package's package.json "scripts" and any locally referenced
// script files STATICALLY from the on-disk tree, and adds the install-time
// subgraph (hook / referenced-artifact / sink nodes and their edges) to g.
//
// Nothing is executed (Decision D-04). If a package's directory is not present
// (a pre-install tree with no node_modules), that package is simply skipped —
// the lockfile-level hasInstallScript fact still stands via VC-002a, and the
// gap is not papered over.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	root := rootDir(path)

	absRoot, _ := filepath.Abs(root)

	var firstErr error
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		relDir := n.Attr["npm.path"]
		if relDir == "" {
			continue
		}
		pkgDir := filepath.Join(root, filepath.FromSlash(relDir))
		// Guard: the resolved pkgDir must stay within the project root.
		// A crafted lockfile with a packages key containing ".." could
		// otherwise escape the project tree via filepath.Join resolution.
		absPkgDir, err := filepath.Abs(pkgDir)
		if err != nil || !isUnderDir(absPkgDir, absRoot) {
			continue
		}
		manifestPath := filepath.Join(pkgDir, "package.json")

		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			continue // not installed on disk; nothing to extract statically
		}
		var m pkgManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("npm: parsing %s: %w", manifestPath, err)
			}
			continue
		}
		if len(m.Scripts) == 0 {
			continue
		}

		// Reader scoped to this package directory; refuses to escape it.
		read := func(rel string) ([]byte, bool) {
			clean := filepath.Clean(filepath.FromSlash(rel))
			if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
				return nil, false
			}
			b, err := os.ReadFile(filepath.Join(pkgDir, clean))
			if err != nil {
				return nil, false
			}
			return b, true
		}

		surface := installsurface.Analyze(m.Scripts, read)
		addSurfaceToGraph(g, n, surface)
	}
	return firstErr
}

// addSurfaceToGraph materializes a Surface as install-time nodes and edges
// hanging off the package node. These are FACTS; no risk state is set here.
func addSurfaceToGraph(g *graph.Graph, pkg *graph.Node, s installsurface.Surface) {
	for _, h := range s.Hooks {
		hookID := "hook:" + pkg.ID + "#" + h.Name
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
			if len(a.Evidence) > 0 {
				an.Attr["artifact.evidence"] = strings.Join(a.Evidence, ",")
			}
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
	return s[:n] + "…"
}

// isUnderDir reports whether child is a path inside parent. Both must be
// absolute (which callers guarantee via filepath.Abs).
func isUnderDir(child, parent string) bool {
	// Normalize trailing separators so the prefix check is safe.
	p := parent + string(filepath.Separator)
	return strings.HasPrefix(child+string(filepath.Separator), p)
}
