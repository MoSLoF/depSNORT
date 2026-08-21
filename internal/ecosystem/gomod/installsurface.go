package gomod

import (
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/securefs"
)

// maxGoFiles bounds how many .go files the install-surface walk reads from one
// module. Go has no depth cap (OPU-22), but a per-module file-count ceiling keeps
// a pathologically large or generated tree from dominating a scan. A real module
// is far under this; hitting it is disclosed as a gap, not a silent truncation.
const maxGoFiles = 5000

// ExtractInstallSurface implements ecosystem.InstallSurfaceExtractor (Decision
// D-26) for Go modules (OPU-28).
//
// Go runs no package code at `go get` or `go build` by design, so it has no
// install/postinstall analog; its build-surface execution points are the
// `//go:generate` directive, cgo `#cgo` flag injection, a build-tag-gated init,
// and a `go run <module>@<version>` remote runner — all classified by
// installsurface.AnalyzeGo. The ROOT module's own .go files are scanned and
// attributed to the root gomod node; each DEPENDENCY's .go files are scanned from
// its vendored copy (vendor/<module-path>/) or the module cache
// ($GOMODCACHE/<escaped-path>@<version>/) and attributed to that dependency node.
//
// Everything is read STATICALLY through securefs (containment + size caps) —
// nothing is executed (Decision D-04). A dependency whose source is not on disk
// (not vendored, not in the cache) is disclosed as a coverage gap, not skipped
// silently.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)
	reader, err := securefs.NewReader(dir)
	if err != nil {
		return err
	}
	var gaps instsurf.Gaps

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}

	// ---- root module scan ----
	rootSources := collectGoSourcesUnder(reader, ".", rootSkipDir, &gaps, "")
	if surface := installsurface.AnalyzeGo(rootSources); len(surface.Hooks) > 0 {
		for _, n := range g.SortedNodes() {
			if n.Kind == graph.KindPackage && n.Ecosystem == "gomod" && roots[n.ID] {
				instsurf.AddToGraph(g, n, surface)
			}
		}
	}

	// ---- dependency scan (vendor / module cache) ----
	var deps []*graph.Node
	depPaths := map[string]bool{}
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindPackage && n.Ecosystem == "gomod" && !roots[n.ID] {
			deps = append(deps, n)
			depPaths[n.Name] = true
		}
	}
	modcache := goModCacheDir()
	for _, n := range deps {
		scanGoDependency(g, n, reader, modcache, depPaths, &gaps)
	}

	return gaps.Err()
}

// scanGoDependency locates a dependency module's source — its vendored copy first
// (in-project, containment-checked), then the module cache (out-of-project) — walks
// its .go files, and attributes any install-surface hooks to the dependency node.
// A module path or version that is not a clean, traversal-free identifier is
// refused; a module absent from both locations is a disclosed coverage gap.
func scanGoDependency(g *graph.Graph, n *graph.Node, projectReader *securefs.Reader, modcache string, depPaths map[string]bool, gaps *instsurf.Gaps) {
	if !cleanModuleIdent(n.Name) || !cleanModuleIdent(n.Version) {
		gaps.AddReason(n.ID, n.Name+"@"+n.Version, instsurf.GapIdentityMismatch, nil)
		return
	}

	// 1. vendored copy: vendor/<module-path>/, inside the project. Contains confirms
	// the path exists and is contained (securefs.Exists is file-only, so it cannot
	// test a directory); a contained non-directory degrades to an empty walk + gap.
	vendorRel := filepath.Join("vendor", filepath.FromSlash(n.Name))
	if projectReader.Contains(vendorRel) {
		// Skip a nested subdirectory that is ANOTHER dependency's vendored root, so
		// a submodule's findings are attributed to it, not to this parent module.
		skip := func(childRel, name string) bool {
			if baseSkipDir(name) {
				return true
			}
			return depPaths[n.Name+"/"+filepath.ToSlash(childRel)]
		}
		attributeGoDeps(g, n, collectGoSourcesUnder(projectReader, vendorRel, skip, gaps, n.ID))
		return
	}

	// 2. module cache: $GOMODCACHE/<escaped-path>@<escaped-version>/, out of project.
	// Cache dirs are one module@version each (a submodule is a separate dir), so no
	// nested-module skip is needed.
	if modcache != "" {
		cacheDir := filepath.Join(modcache, filepath.FromSlash(escapeGoCasePath(n.Name))+"@"+escapeGoCasePath(n.Version))
		if info, err := os.Stat(cacheDir); err == nil && info.IsDir() {
			depReader, err := securefs.NewReader(cacheDir)
			if err != nil {
				gaps.Add(n.ID, cacheDir, err)
				return
			}
			attributeGoDeps(g, n, collectGoSourcesUnder(depReader, ".", baseSkipDirRel, gaps, n.ID))
			return
		}
	}

	gaps.AddReason(n.ID, n.Name+"@"+n.Version, instsurf.GapUnavailable, nil)
}

// attributeGoDeps analyzes a dependency's collected sources and, when they yield
// install-surface hooks, materializes them onto the dependency node.
func attributeGoDeps(g *graph.Graph, n *graph.Node, sources map[string]string) {
	if surface := installsurface.AnalyzeGo(sources); len(surface.Hooks) > 0 {
		instsurf.AddToGraph(g, n, surface)
	}
}

// collectGoSourcesUnder walks startRel within reader and returns every readable,
// non-test .go file's contents keyed by its path RELATIVE TO startRel (the label a
// hook carries). skipDir(childRel, name) decides whether to descend into a
// subdirectory (childRel is its path relative to startRel; name its base). It
// descends real subdirectories only — an os.DirEntry symlink reports
// IsDir()==false, so symlinked directories are not followed and there is no
// traversal cycle. Unreadable files and directories are recorded as gaps.
func collectGoSourcesUnder(reader *securefs.Reader, startRel string, skipDir func(childRel, name string) bool, gaps *instsurf.Gaps, gapPkg string) map[string]string {
	sources := map[string]string{}
	count := 0

	var walk func(rel, relToStart string)
	walk = func(rel, relToStart string) {
		if count >= maxGoFiles {
			return
		}
		entries, err := reader.ReadDir(rel)
		if err != nil {
			gaps.Add(gapPkg, rel, err)
			return
		}
		for _, e := range entries {
			if count >= maxGoFiles {
				return
			}
			name := e.Name()
			child := filepath.Join(rel, name)
			childRel := name
			if relToStart != "" {
				childRel = filepath.Join(relToStart, name)
			}
			if e.IsDir() {
				if skipDir(childRel, name) {
					continue
				}
				walk(child, childRel)
				continue
			}
			if !strings.HasSuffix(name, ".go") {
				continue
			}
			count++
			b, err := reader.ReadFile(child)
			if err != nil {
				gaps.Add(gapPkg, child, err)
				continue
			}
			sources[filepath.ToSlash(childRel)] = string(b)
		}
	}
	start := startRel
	if start == "" {
		start = "."
	}
	walk(start, "")
	return sources
}

// baseSkipDir reports whether a directory NAME is one Go excludes from a build:
// test fixtures and the '.'/'_'-prefixed directories the go tool ignores.
func baseSkipDir(name string) bool {
	if name == "testdata" {
		return true
	}
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// baseSkipDirRel adapts baseSkipDir to the collectGoSourcesUnder skip signature.
func baseSkipDirRel(_ string, name string) bool { return baseSkipDir(name) }

// rootSkipDir is the root-module skip: baseSkipDir plus vendor/, whose contents are
// attributed to their own dependency nodes rather than the root.
func rootSkipDir(_ string, name string) bool { return name == "vendor" || baseSkipDir(name) }

// cleanModuleIdent reports whether a module path or version is a clean identifier
// with no traversal, so it cannot steer a cache lookup outside GOMODCACHE or a
// vendor lookup outside the project. Slash-separated segments, none empty, ".", or
// "..", and no NUL or backslash.
func cleanModuleIdent(s string) bool {
	if s == "" || strings.ContainsAny(s, "\x00\\") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// escapeGoCasePath applies the Go module cache's case-encoding: an uppercase letter
// U is stored as "!u". Without it a module or version with an uppercase letter is
// looked up at the wrong cache path. (Replicated locally — goproxy's equivalent is
// unexported and this package keeps its dependency footprint minimal.)
func escapeGoCasePath(s string) string {
	if strings.ToLower(s) == s {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// goModCacheDir resolves the Go module cache root: $GOMODCACHE, else
// $GOPATH/pkg/mod (first GOPATH entry), else $HOME/go/pkg/mod. Empty if none
// resolves.
func goModCacheDir() string {
	if c := os.Getenv("GOMODCACHE"); c != "" {
		return c
	}
	if gp := os.Getenv("GOPATH"); gp != "" {
		if i := strings.IndexByte(gp, os.PathListSeparator); i >= 0 {
			gp = gp[:i]
		}
		return filepath.Join(gp, "pkg", "mod")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "go", "pkg", "mod")
	}
	return ""
}
