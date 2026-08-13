package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/securefs"
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

	// One contained reader for the whole project tree (finding F-03): every read
	// below is checked for traversal, absolute escape, and symlinks pointing out
	// of root, and is refused if the target is not a regular file or is oversized.
	reader, err := securefs.NewReader(root)
	if err != nil {
		return fmt.Errorf("npm: %w", err)
	}
	absRoot := reader.Root()

	// Refused reads are recorded as typed gaps, not swallowed (R-01): a symlink
	// planted where a package directory belongs must make the scan incomplete,
	// or an attacker can hide an install hook simply by making it unreadable.
	var gaps instsurf.Gaps
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage {
			continue
		}
		relDir := n.Attr["npm.path"]
		if relDir == "" {
			continue
		}
		pkgDir := filepath.Join(root, filepath.FromSlash(relDir))
		// Cheap lexical pre-check that the package dir stays under root; the
		// reader repeats the containment check (and adds symlink resolution) on
		// every read, so this is just an early skip for a crafted "npm.path".
		absPkgDir, err := filepath.Abs(pkgDir)
		if err != nil || !isUnderDir(absPkgDir, absRoot) {
			// A lockfile path that escapes the root is itself a planted signal.
			gaps.AddReason(n.ID, pkgDir, instsurf.GapContainment, err)
			continue
		}
		manifestPath := filepath.Join(absPkgDir, "package.json")

		raw, err := reader.ReadFile(manifestPath)
		if err != nil {
			// Absent (no node_modules) is normal; refused is not.
			gaps.Add(n.ID, manifestPath, err)
			continue
		}
		var m pkgManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			gaps.AddReason(n.ID, manifestPath, instsurf.GapParse, err)
			continue
		}
		if len(m.Scripts) == 0 {
			continue
		}

		// Reader scoped to this package directory; the contained reader enforces
		// root containment and symlink safety, this closure keeps it within the
		// package subtree and rejects absolute / traversal script refs up front.
		read := func(rel string) ([]byte, bool) {
			clean := filepath.Clean(filepath.FromSlash(rel))
			if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
				gaps.AddReason(n.ID, rel, instsurf.GapContainment, nil)
				return nil, false
			}
			p := filepath.Join(absPkgDir, clean)
			b, err := reader.ReadFile(p)
			if err != nil {
				// A hook referencing a script we cannot read means the chain is
				// only partly known — the unread file is where the payload
				// would be.
				gaps.Add(n.ID, p, err)
				return nil, false
			}
			return b, true
		}

		surface := installsurface.Analyze(m.Scripts, read)
		addSurfaceToGraph(g, n, surface)
	}
	return gaps.Err()
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
