package pypi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// ExtractInstallSurface implements ecosystem.InstallSurfaceExtractor.
//
// For each resolved package, it fetches the source distribution from PyPI
// (cached), extracts setup.py and pyproject.toml, and analyzes them STATICALLY
// for install-time capabilities. Nothing is executed (Decision D-04).
//
// If the adapter has no SdistFetcher configured (nil), extraction is silently
// skipped — this is the expected behavior in offline mode or when the user
// disables install-surface analysis.
func (a *Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}

	projectDir := filepath.Dir(path)
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		projectDir = path
	}

	ctx := context.Background()
	var firstErr error

	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		if n.Ecosystem != "pypi" {
			continue
		}

		if roots[n.ID] {
			// Root project: read setup.py/pyproject.toml from the local
			// project directory rather than fetching from PyPI.
			extractLocalPython(projectDir, g, n)
			continue
		}

		if a.Sdist == nil {
			continue
		}
		if n.Name == "" || n.Version == "" {
			continue
		}

		files, err := a.Sdist.Fetch(ctx, n.Name, n.Version)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("pypi install-surface: %s@%s: %w", n.Name, n.Version, err)
			}
			continue
		}

		if files.WheelOnly {
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			n.Attr["pypi.wheel_only"] = "true"
			continue
		}

		surface := installsurface.AnalyzePython(files.SetupPy, files.PyprojectToml, files.PthFiles)
		if len(surface.Hooks) > 0 {
			addPySurfaceToGraph(g, n, surface)
		}
	}
	return firstErr
}

// extractLocalPython reads setup.py and pyproject.toml from the local project
// directory and analyzes them for install-time capabilities. This handles the
// root project, which isn't published on PyPI and can't be fetched via sdist.
func extractLocalPython(dir string, g *graph.Graph, n *graph.Node) {
	setupPy, _ := os.ReadFile(filepath.Join(dir, "setup.py"))
	pyprojectToml, _ := os.ReadFile(filepath.Join(dir, "pyproject.toml"))

	if len(setupPy) == 0 && len(pyprojectToml) == 0 {
		return
	}

	surface := installsurface.AnalyzePython(string(setupPy), string(pyprojectToml), nil)
	if len(surface.Hooks) > 0 {
		addPySurfaceToGraph(g, n, surface)
	}
}

// addPySurfaceToGraph materializes a Python install Surface as install-time
// nodes and edges hanging off the package node. These are FACTS; no risk state
// is set here — the VC-002 checks judge them.
func addPySurfaceToGraph(g *graph.Graph, pkg *graph.Node, s installsurface.Surface) {
	for _, h := range s.Hooks {
		hookID := "hook:" + pkg.ID + "#" + sanitizeHookName(h.Name)
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

func sanitizeHookName(name string) string {
	return strings.ReplaceAll(name, ":", "_")
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
