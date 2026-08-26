package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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
	// Exports is the modern conditional-exports field. When present it REPLACES
	// main for Node's own resolution, so a package can expose its entry — and a
	// loader that runs on import — without setting main at all. Its shape is not
	// statically typed (a string, a conditions object, a subpath map, or those
	// nested), so it is kept raw and walked by exportsEntryPaths.
	Exports json.RawMessage `json:"exports"`
	// Private is the npm "private": true flag — set on application roots that
	// are not meant to be published as installable packages (OPU-38). When true,
	// the project's own install scripts are developer tooling, not consumer-facing
	// install hooks, and are excluded from the publishable-package hook analysis.
	Private bool `json:"private"`
}

// maxExportsDepth bounds recursion into an "exports" value. Real maps nest
// three or four levels (subpath -> condition -> condition -> path); anything
// deeper is malformed or hostile, and an unbounded walk over attacker-supplied
// JSON is a stack-exhaustion vector.
const maxExportsDepth = 8

// maxExportsEntries bounds how many paths one exports map contributes. The
// manifest's own size is already bounded by the contained reader, and real
// packages with many subpaths use wildcard patterns (skipped below) rather than
// enumerating hundreds of them, so this is unreachable for legitimate input and
// exists only to bound a crafted manifest.
const maxExportsEntries = 256

// exportsEntryPaths walks a package.json "exports" value and returns every
// package-relative module path reachable through it, in a deterministic order.
//
// Every exported path is load-time reachable: importing "pkg/feature" executes
// whatever "./feature" maps to, exactly as importing "pkg" executes ".". So all
// of them are collected, not just the "." subpath — a loader hidden behind a
// secondary subpath runs on import just the same.
//
// Map keys are sorted before descending: Go randomizes map iteration, and the
// candidate list feeds graph node construction, which the determinism tests
// require to be stable across runs.
func exportsEntryPaths(raw json.RawMessage) []string {
	paths, _ := exportsPathsMatching(raw, false)
	return paths
}

// exportsTruncation reports which exports-walk bounds stopped short, if any.
// The walk itself stays pure; disclosure happens where a Gaps sink exists.
func exportsTruncation(raw json.RawMessage) []string {
	_, concreteTrunc := exportsPathsMatching(raw, false)
	_, wildcardTrunc := exportsPathsMatching(raw, true)
	// Both halves walk the same tree, so a bound trips identically in each.
	// Report it once.
	if len(concreteTrunc) > 0 {
		return concreteTrunc
	}
	return wildcardTrunc
}

// exportsWildcardTargets returns the wildcard TARGETS in an exports value (the
// right-hand side, e.g. "./src/features/*.js"). They name a set of files rather
// than one, so they are resolved against the tree by resolveExportsWildcards
// rather than used as candidates directly.
func exportsWildcardTargets(raw json.RawMessage) []string {
	paths, _ := exportsPathsMatching(raw, true)
	return paths
}

// exportsPathsMatching is the shared walk. wantWildcard selects which half of
// the paths to return: the concrete ones, or the wildcard patterns.
func exportsPathsMatching(raw json.RawMessage, wantWildcard bool) (paths, truncated []string) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// A malformed exports value is not fatal: main/module and the
		// conventional index.* candidates below still apply.
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	var hitDepth, hitEntries bool
	var walk func(node any, depth int)
	walk = func(node any, depth int) {
		// Reached only where there is more to descend into, so setting these
		// means real truncation rather than a walk that simply finished.
		if depth > maxExportsDepth {
			hitDepth = true
			return
		}
		if len(out) >= maxExportsEntries {
			hitEntries = true
			return
		}
		switch t := node.(type) {
		case string:
			// Only relative paths name a file inside this package. Bare
			// specifiers ("node:fs", "another-pkg") resolve elsewhere.
			if !strings.HasPrefix(t, "./") {
				return
			}
			// A wildcard pattern names a SET; it is resolved against the tree
			// separately. Each call returns one half or the other.
			if strings.Contains(t, "*") != wantWildcard {
				return
			}
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		case []any:
			// Fallback array: any element may be the one Node resolves.
			for _, e := range t {
				walk(e, depth+1)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k], depth+1)
			}
		}
		// A null value blocks a subpath and contributes nothing.
	}
	walk(v, 0)
	if hitDepth {
		truncated = append(truncated, fmt.Sprintf("exports nesting capped at depth %d", maxExportsDepth))
	}
	if hitEntries {
		truncated = append(truncated, fmt.Sprintf("exports paths capped at %d", maxExportsEntries))
	}
	return out, truncated
}

// npmEntryCandidates returns the entry modules an import of this package could
// load, in priority order, deduplicated and normalized to package-relative
// slash paths. main/module, every path reachable through `exports`, and the
// conventional index.* cover the common cases — including the RedC2 loader,
// whose package.json sets "main": "dist/index.mjs", and modern packages that
// ship an `exports` map with no main at all.
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
	for _, p := range exportsEntryPaths(m.Exports) {
		add(p)
	}
	add("index.js")
	add("index.mjs")
	add("index.cjs")
	return out
}

// Bounds on wildcard resolution. Unlike the exports walk above, this one
// touches the filesystem, so it is bounded on three axes: how many matches one
// package may contribute (each is read and scanned), how many directory entries
// may be examined finding them, and how deep the walk may go.
const (
	maxExportsWildcardMatches = 64
	maxExportsWildcardVisits  = 4096
	maxExportsWildcardDepth   = 16
)

// wildcardPrefixSuffix splits a wildcard target into the literal text before
// its first `*` and after its last.
//
// Node substitutes the SAME captured string for every `*` in a target, so a
// target with two of them constrains the match more tightly than prefix+suffix
// alone. Solving that exactly is only tractable for a single `*`; with more,
// prefix/suffix matching yields a SUPERSET. That is the safe direction for a
// scanner — it analyzes files that may not be reachable rather than missing
// ones that are — and matches the existing posture, which already scans
// index.js/index.mjs/index.cjs whether or not they are exported.
func wildcardPrefixSuffix(target string) (prefix, suffix string, ok bool) {
	p := strings.TrimPrefix(target, "./")
	first := strings.Index(p, "*")
	if first < 0 {
		return "", "", false
	}
	last := strings.LastIndex(p, "*")
	prefix, suffix = p[:first], p[last+1:]
	// A target that escapes the package is refused here as well as by the
	// contained reader below.
	if strings.Contains(prefix, "..") || strings.Contains(suffix, "..") {
		return "", "", false
	}
	return prefix, suffix, true
}

// staticDirOf returns the deepest fully-literal directory of a prefix, which is
// where the walk can start: "src/features/" -> "src/features", "dist/feat-" ->
// "dist" (the trailing text is a partial filename, not a directory).
func staticDirOf(prefix string) string {
	i := strings.LastIndex(prefix, "/")
	if i < 0 {
		return ""
	}
	return prefix[:i]
}

// resolveExportsWildcards enumerates the real files a package's wildcard export
// targets reach, returning package-relative slash paths.
//
// Node's `*` in a subpath pattern matches any substring INCLUDING "/", so
// "./f/*.js" reaches "./f/deep/nested/loader.js". That is why this is a
// recursive walk rather than a single-directory match.
//
// Every read and listing goes through the contained reader, so a symlink out of
// the package is refused rather than followed. os.ReadDir returns entries
// sorted by name and the target list arrives sorted, so the result is
// deterministic without further sorting.
//
// When a bound stops the walk with material still unexamined, that is recorded
// as a GapTruncated coverage gap rather than returned silently (R-01): a bound
// that quietly drops entry modules reports "we looked and found nothing" when
// the truth is "we stopped looking", which is the invisibility the gap layer
// exists to prevent. One gap per package, naming which bounds tripped — not one
// per skipped directory, which would drown the report it is meant to inform.
func resolveExportsWildcards(reader *securefs.Reader, baseDir string, raw json.RawMessage, pkgID string, gaps *instsurf.Gaps) []string {
	targets := exportsWildcardTargets(raw)
	if len(targets) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	visits := 0
	var hitMatches, hitVisits, hitDepth bool

	// bounded reports whether a bound stops us here. Every call site is reached
	// only when there is more to examine, so setting the flag means real
	// truncation, never a walk that simply finished.
	bounded := func(depth int) bool {
		switch {
		case depth > maxExportsWildcardDepth:
			hitDepth = true
		case len(out) >= maxExportsWildcardMatches:
			hitMatches = true
		case visits >= maxExportsWildcardVisits:
			hitVisits = true
		default:
			return false
		}
		return true
	}

	for _, t := range targets {
		prefix, suffix, ok := wildcardPrefixSuffix(t)
		if !ok {
			continue
		}
		var walk func(relDir string, depth int)
		walk = func(relDir string, depth int) {
			if bounded(depth) {
				return
			}
			dirPath := baseDir
			if relDir != "" {
				dirPath = filepath.Join(baseDir, filepath.FromSlash(relDir))
			}
			entries, err := reader.ReadDir(dirPath)
			if err != nil {
				// Absent or refused. A package that does not ship the directory
				// its own exports name is normal, not a coverage gap.
				return
			}
			for _, e := range entries {
				// depth is not re-checked here: this loop is inside a directory
				// already admitted at this depth.
				if bounded(depth) {
					return
				}
				visits++
				name := e.Name()
				childRel := name
				if relDir != "" {
					childRel = relDir + "/" + name
				}
				if e.IsDir() {
					// A nested node_modules is other packages, analyzed on
					// their own nodes; dot-directories are not shipped code.
					if name == "node_modules" || strings.HasPrefix(name, ".") {
						continue
					}
					walk(childRel, depth+1)
					continue
				}
				if !strings.HasPrefix(childRel, prefix) || !strings.HasSuffix(childRel, suffix) {
					continue
				}
				// Reject an overlap where prefix and suffix share characters:
				// `*` has to stand for something.
				if len(childRel) < len(prefix)+len(suffix) {
					continue
				}
				if !seen[childRel] {
					seen[childRel] = true
					out = append(out, childRel)
				}
			}
		}
		walk(staticDirOf(prefix), 0)
	}

	if gaps != nil && (hitMatches || hitVisits || hitDepth) {
		var which []string
		if hitMatches {
			which = append(which, fmt.Sprintf("match cap %d", maxExportsWildcardMatches))
		}
		if hitVisits {
			which = append(which, fmt.Sprintf("visit cap %d", maxExportsWildcardVisits))
		}
		if hitDepth {
			which = append(which, fmt.Sprintf("depth cap %d", maxExportsWildcardDepth))
		}
		gaps.AddReason(pkgID, "package.json (exports wildcard resolution)", instsurf.GapTruncated,
			fmt.Errorf("%s reached; wildcard-reachable entry modules past it were not analyzed",
				strings.Join(which, ", ")))
	}
	return out
}

// npmEntryCandidatesResolved is npmEntryCandidates plus the files reached by
// wildcard export targets, which need the tree to enumerate. Deduplicated
// against the static candidates: a file can be both a concrete export and a
// wildcard match.
func npmEntryCandidatesResolved(m pkgManifest, reader *securefs.Reader, baseDir, pkgID string, gaps *instsurf.Gaps) []string {
	cands := npmEntryCandidates(m)
	have := make(map[string]bool, len(cands))
	for _, c := range cands {
		have[c] = true
	}
	if gaps != nil {
		for _, t := range exportsTruncation(m.Exports) {
			gaps.AddReason(pkgID, "package.json (exports)", instsurf.GapTruncated, errors.New(t))
		}
	}
	for _, w := range resolveExportsWildcards(reader, baseDir, m.Exports, pkgID, gaps) {
		if !have[w] {
			have[w] = true
			cands = append(cands, w)
		}
	}
	return cands
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
// Nothing is executed (Decision D-04). If a dependency's directory is not
// present (a pre-install tree with no node_modules), that package is recorded
// as a source-unavailable coverage gap (D-148): the lockfile-level
// hasInstallScript fact still stands via VC-002a, but that flag is the
// registry's assertion, and the hook CONTENT — the cradle and exfil markers
// VC-002e/f read, and the entry module's load-time chain — was never examined.
// This comment previously said the skip meant "the gap is not papered over";
// with nothing recorded anywhere, papered over is exactly what it was.
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
			// Refused is a typed gap as before. Absent used to be silent —
			// "normal" — which read as examined-and-clean for every dependency
			// of a pre-install tree (D-148). The root stays exempt: its
			// manifest is what discovery keyed on, so it cannot be absent in a
			// tree we are scanning.
			if errors.Is(err, fs.ErrNotExist) && relDir != "." {
				gaps.AddReason(n.ID, manifestPath, instsurf.GapUnavailable,
					errors.New("package source not installed; install hooks and entry modules were not examined"))
			} else {
				gaps.Add(n.ID, manifestPath, err)
			}
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
		for _, cand := range npmEntryCandidatesResolved(m, reader, absPkgDir, n.ID, &gaps) {
			src, err := reader.ReadFile(filepath.Join(absPkgDir, filepath.FromSlash(cand)))
			if err != nil {
				continue
			}
			lt := installsurface.AnalyzeLoadTime(cand, string(src), read)
			for _, t := range lt.Truncated {
				gaps.AddReason(n.ID, cand, instsurf.GapTruncated, errors.New(t))
			}
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
		// Publishable package. Analyze it the same way the main loop analyzes a
		// dependency: lifecycle scripts when present, and ALWAYS the entry module.
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
		if len(m.Scripts) > 0 {
			surface := installsurface.Analyze(m.Scripts, read)
			addSurfaceToGraph(g, n, surface)
		}
		// Load-time (entry-module) analysis: the same gap that exists for
		// lockfile-resolved packages also exists here (OPU-31). This must NOT be
		// gated on the package having lifecycle scripts — a package with no
		// scripts at all whose entry module runs a loader on import is precisely
		// the RedC2 evasion OPU-31 exists to catch, and gating it behind
		// len(m.Scripts) > 0 reinstated that blind spot for publishable roots
		// (the OPU-38 pass shipped with exactly that bug).
		for _, cand := range npmEntryCandidatesResolved(m, reader, absRoot, n.ID, &gaps) {
			src, err := reader.ReadFile(filepath.Join(absRoot, filepath.FromSlash(cand)))
			if err != nil {
				continue
			}
			lt := installsurface.AnalyzeLoadTime(cand, string(src), read)
			for _, t := range lt.Truncated {
				gaps.AddReason(n.ID, cand, instsurf.GapTruncated, errors.New(t))
			}
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

		// D-152: the worm loop. Drawn here as well as in instsurf.AddToGraph
		// because npm, PyPI and Composer each hand-roll a near-verbatim copy of
		// that function; wiring the edge only in the shared helper left the ONE
		// ecosystem Shai-Hulud actually targets without it, so a live npm worm
		// produced a VC-002k finding over a graph that showed no loop. The
		// conformance test in internal/ecosystem/conformance keeps the copies
		// from drifting apart again.
		if h.HasCap(installsurface.CapPropagate) {
			g.AddEdge(hookID, pkg.ID, graph.EdgeRepublish)
		}

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
