package pypi

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/securefs"
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
	var gaps instsurf.Gaps
	// processed dedupes PEP 517 build-backend resolution: a backend used by
	// several consumers is fetched and analyzed once, not once per consumer.
	processed := map[string]bool{}

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
			a.extractLocalPython(ctx, projectDir, g, n, &gaps, processed)
			continue
		}

		if n.Name == "" || n.Version == "" {
			continue
		}
		if a.Sdist == nil {
			// No fetcher configured, so this dependency's install surface is
			// unexamined. Staying silent would report that as "nothing to
			// find" (R-01), which is exactly the confusion D-141 corrected for
			// the offline path.
			gaps.AddReason(n.ID, n.Name+"@"+n.Version, instsurf.GapUnavailable, nil)
			continue
		}

		files, err := a.Sdist.Fetch(ctx, n.Name, n.Version)
		if err != nil {
			// Every sdist failure — network, integrity, or a hostile-input
			// bound — is a gap: the package's install surface went unexamined
			// (R-01 / R-02).
			gaps.AddReason(n.ID, n.Name+"@"+n.Version, instsurf.GapUnreadable, err)
			continue
		}

		if files.WheelOnly {
			if n.Attr == nil {
				n.Attr = map[string]string{}
			}
			n.Attr["pypi.wheel_only"] = "true"
			// A wheel has no setup.py/build-backend to analyze (build-time/sdist
			// concepts) — only .pth files recovered from the wheel's zip, if any.
			if len(files.PthFiles) == 0 {
				continue
			}
			surface := installsurface.AnalyzePython("", "", files.PthFiles)
			if len(surface.Hooks) > 0 {
				addPySurfaceToGraph(g, n, surface)
			}
			continue
		}

		a.resolveBuildBackend(ctx, g, n, files.PyprojectToml, processed, &gaps)

		surface := installsurface.AnalyzePython(files.SetupPy, files.PyprojectToml, files.PthFiles)
		if len(surface.Hooks) > 0 {
			addPySurfaceToGraph(g, n, surface)
		}
	}
	return gaps.Err()
}

// extractLocalPython reads setup.py and pyproject.toml from the local project
// directory and analyzes them for install-time capabilities. This handles the
// root project, which isn't published on PyPI and can't be fetched via sdist.
func (a *Adapter) extractLocalPython(ctx context.Context, dir string, g *graph.Graph, n *graph.Node, gaps *instsurf.Gaps, processed map[string]bool) {
	// Contained reads (F-03): a setup.py or pyproject.toml symlinked out of the
	// project is refused rather than followed — and that refusal is recorded as
	// a gap rather than silently read as "this project has no setup.py" (R-01).
	reader, err := securefs.NewReader(dir)
	if err != nil {
		gaps.Add(n.ID, dir, err)
		return
	}
	read := func(name string) []byte {
		b, err := reader.ReadFile(name)
		if err != nil {
			gaps.Add(n.ID, filepath.Join(dir, name), err)
			return nil
		}
		return b
	}
	setupPy := read("setup.py")
	pyprojectToml := read("pyproject.toml")

	if len(setupPy) == 0 && len(pyprojectToml) == 0 {
		return
	}

	a.resolveBuildBackend(ctx, g, n, string(pyprojectToml), processed, gaps)

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
