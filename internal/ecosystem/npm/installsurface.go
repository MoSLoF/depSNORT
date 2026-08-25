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
	// Main/Module are the entry modules a require()/import loads. They are read
	// for load-time execution analysis (OPU-31): a package with no lifecycle
	// script can still run a payload the instant it is imported.
	Main   string `json:"main"`
	Module string `json:"module"`
	// Private is the npm "private": true flag — set on application roots that
	// are not meant to be published as installable packages (OPU-38). When true,
	// the project's own install scripts are developer tooling, not consumer-facing
	// install hooks, and are excluded from the publishable-package hook analysis.
	Private bool `json:"private"`
}

// npmEntryCandidates returns the entry modules an import of this package could
// load, in priority order, deduplicated and normalized to package-relative
// slash paths. `exports`-as-object is not resolved in this pass (documented
// limitation); main/module plus the conventional index.* cover the common cases
// including the RedC2 loader, whose package.json sets "main": "dist/index.mjs".
func npmEntryCandidates(m pkgManifest) []string {
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		p = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(filepath.FromSlash(p))), "./")
		if p == "" || strings.HasPrefix(p, "..") {
			return
		}
		for _, x := range out {
			if x == p {
				return
			}
		}
		out = append(out, p)
	}
	add(m.Main)
	add(m.Module)
	add("index.js")
	add("index.mjs")
	add("index.cjs")
	return out
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

		// Lifecycle-script install surface (VC-002a..).
		if len(m.Scripts) > 0 {
			surface := installsurface.Analyze(m.Scripts, read)
			addSurfaceToGraph(g, n, surface)
		}

		// Load-time (import-time) install surface (OPU-31): the entry module runs
		// on import even with NO lifecycle script — the RedC2 evasion. A missing
		// entry file (pre-install tree, or a candidate the package does not ship)
		// is normal and read quietly; only a referenced sibling that is refused
		// becomes a gap (via the `read` closure passed to AnalyzeLoadTime).
		for _, cand := range npmEntryCandidates(m) {
			src, err := reader.ReadFile(filepath.Join(absPkgDir, filepath.FromSlash(cand)))
			if err != nil {
				continue
			}
			lt := installsurface.AnalyzeLoadTime(cand, string(src), read)
			addSurfaceToGraph(g, n, lt)
		}
	}

	// Project-root AI-agent config scan (OPU-37): scan any AI-coding-agent /
	// editor auto-run configuration files found at the project root. These are
	// the files that Miasma-family malware writes via a package's postinstall
	// hook (caught by OPU-35/36's persistenceMarkers when the hook is scanned).
	// This pass catches a different case: the file is already committed to the
	// repo — either because an earlier install wrote it before the package was
	// removed, or because the attack placed it directly. Both cases leave a file
	// that survives npm uninstall and re-executes on every session/folder-open.
	// Only files whose content carries suspicious capability markers (network
	// egress, obfuscation, persistence writes — the same signals install hooks
	// are flagged for) produce findings; a legitimate watch command or a simple
	// rule file with no capability markers scores nothing (OPU-35 FP reasoning
	// applies here too — confirmed against vscode-eslint and vscode-gitlens
	// before landing).
	for _, rel := range installsurface.AIAgentConfigFiles {
		// absRoot, not root: root may be a relative path (e.g. a bare directory
		// name passed on the command line), and filepath.Join(root, rel) then
		// produces a relative candidate that reader.ReadFile re-joins onto its
		// OWN absolute root — doubling the directory component and silently
		// missing every file except when root happens to be "." or already
		// absolute (found via live-fire testing: `depsnort scan someRelativeDir`
		// scanned clean while `depsnort scan .` from inside the same directory,
		// or an absolute path to it, correctly found the same fixture).
		candidate := filepath.Join(absRoot, filepath.FromSlash(rel))
		src, err := reader.ReadFile(candidate)
		if err != nil {
			continue // absent or unreadable — normal
		}
		if surface := installsurface.AnalyzeAIAgentConfig(rel, string(src)); len(surface.Hooks) > 0 {
			// Attribute the finding to the project root, not to any individual
			// package (the file is project-level, not inside node_modules). We
			// use a synthetic root node ID, keyed on absRoot so the same project
			// scanned via a relative or absolute path yields the same node.
			rootPkg := g.Get("project-root:" + absRoot)
			if rootPkg == nil {
				rootPkg = g.AddNode(&graph.Node{
					ID:        "project-root:" + absRoot,
					Kind:      graph.KindPackage,
					Ecosystem: "npm",
					Name:      "(project root)",
				})
			}
			addSurfaceToGraph(g, rootPkg, surface)
		}
	}
	// OPU-38: Root-package install-hook analysis (publishable package mode).
	//
	// The main loop above is keyed on npm.path, which lockfile-resolved packages
	// carry as "." (root) or "node_modules/name" (dependency). Root project nodes
	// created from a bare package.json (no lockfile) carry npm.source but NOT
	// npm.path, so they are silently skipped by the `relDir == ""` guard above.
	// That gap is intentional for the common case (scanning your own project: your
	// own install scripts are developer tooling, not supply-chain risk), but wrong
	// for the specific use case this scan was run on: evaluating a PUBLISHABLE npm
	// package before adding it as a dependency. A package's install hook is exactly
	// what runs on every consumer's machine during `npm install` — the canonical
	// supply-chain attack surface.
	//
	// Condition for publishable-package mode (OPU-38):
	//   1. The node is a registered graph root (g.Roots).
	//   2. It has no npm.path (was NOT already analyzed in the main loop).
	//   3. Its package.json does NOT carry "private": true. Private packages are
	//      application roots — their postinstall/prepare scripts are build steps
	//      (next build, husky install) that would FP at high rate if scored with
	//      the same lens as a dependency's install hook.
	//
	// Validated against: Medium/phantomjs (phantomjs-prebuilt@2.1.16, no lockfile,
	// publishable, install: "node install.js" — download + SHA-256 verify + exec).
	// FP calibration: four large VS Code extension repos (all have "private": true)
	// and the vscode-eslint/gitlens repos — none triggered under this condition.
	roots := make(map[string]bool, len(g.Roots))
	for _, id := range g.Roots {
		roots[id] = true
	}
	for _, n := range g.SortedNodes() {
		if !roots[n.ID] {
			continue // not a root
		}
		if n.Attr["npm.path"] != "" {
			continue // already handled in the main loop (lockfile path)
		}
		manifestPath := filepath.Join(absRoot, "package.json")
		raw, err := reader.ReadFile(manifestPath)
		if err != nil {
			continue // unreadable or absent — not an error for OPU-38's purpose
		}
		var m pkgManifest
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		if m.Private {
			// Application root. install scripts are developer tooling, not consumer
			// hooks. Leave them unscored to avoid FPs on build steps.
			continue
		}
		if len(m.Scripts) == 0 {
			continue // nothing to analyze
		}
		// Publishable package with install scripts. Analyze them the same way the
		// main loop analyzes a dependency's hooks.
		read := func(rel string) ([]byte, bool) {
			clean := filepath.Clean(filepath.FromSlash(rel))
			if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
				return nil, false
			}
			b, err := reader.ReadFile(filepath.Join(absRoot, clean))
			if err != nil {
				return nil, false
			}
			return b, true
		}
		surface := installsurface.Analyze(m.Scripts, read)
		addSurfaceToGraph(g, n, surface)
		// Load-time (entry-module) analysis: the same gap that exists for
		// lockfile-resolved packages also exists here (OPU-31).
		for _, cand := range npmEntryCandidates(m) {
			src, err := reader.ReadFile(filepath.Join(absRoot, filepath.FromSlash(cand)))
			if err != nil {
				continue
			}
			lt := installsurface.AnalyzeLoadTime(cand, string(src), read)
			addSurfaceToGraph(g, n, lt)
		}
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
