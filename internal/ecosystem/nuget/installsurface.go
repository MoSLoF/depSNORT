package nuget

import (
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/securefs"
)

// ExtractInstallSurface implements ecosystem.InstallSurfaceExtractor (Decision
// D-26).
//
// A NuGet package can ship:
//   - PowerShell that runs on install (install.ps1) or when the solution opens
//     (init.ps1).
//   - MSBuild .targets/.props files in build/, buildTransitive/,
//     buildMultiTargeting/, or buildCrossTargeting/ that execute arbitrary
//     targets at build time.
//
// Two scopes are checked:
//
//  1. The project root directory — for install hooks that belong to the project
//     itself (existing behavior).
//  2. Each dependency package's extracted directory in the NuGet global packages
//     cache — so build-time payloads shipped by a dependency are attributed to
//     the DEPENDENCY PURL, not the project root.
//
// This reads those files STATICALLY. Nothing is executed (Decision D-04).
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

	// ---- project-root scan ----

	scripts := readPowerShellHooks(reader, "", &gaps)
	msbuildScripts := scanMSBuildDirs(reader, "", &gaps)

	if len(scripts) > 0 || len(msbuildScripts) > 0 {
		for _, n := range g.SortedNodes() {
			if n.Kind != graph.KindPackage || n.Ecosystem != "nuget" || !roots[n.ID] {
				continue
			}
			applyHooks(g, n, scripts, msbuildScripts)
		}
	}

	// ---- dependency-package scan ----
	pkgDirs := nugetPackagesDirs()
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "nuget" || roots[n.ID] {
			continue
		}
		scanDependencyPkg(g, n, pkgDirs, &gaps)
	}

	return gaps.Err()
}

func readPowerShellHooks(reader *securefs.Reader, nodeID string, gaps *instsurf.Gaps) map[string]string {
	scripts := map[string]string{}
	for _, name := range installsurface.NuGetInstallHookNames {
		b, err := reader.ReadFile(name)
		if err != nil {
			gaps.Add(nodeID, name, err)
			continue
		}
		if len(b) > 0 {
			scripts[name] = string(b)
		}
	}
	return scripts
}

// scanMSBuildDirs enumerates the documented NuGet MSBuild directories (build/,
// buildTransitive/, buildMultiTargeting/, buildCrossTargeting/) within the
// reader's root, returning a map of relative-path to file content for .targets
// and .props files. TFM-specific subdirectories (e.g. build/net8.0/) are
// included.
func scanMSBuildDirs(reader *securefs.Reader, nodeID string, gaps *instsurf.Gaps) map[string]string {
	out := map[string]string{}
	for _, msbDir := range installsurface.NuGetMSBuildDirs {
		entries, err := reader.ReadDir(msbDir)
		if err != nil {
			gaps.Add(nodeID, msbDir, err)
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				subDir := filepath.Join(msbDir, name)
				subEntries, err := reader.ReadDir(subDir)
				if err != nil {
					gaps.Add(nodeID, subDir, err)
					continue
				}
				for _, sub := range subEntries {
					ext := strings.ToLower(filepath.Ext(sub.Name()))
					if ext != ".targets" && ext != ".props" {
						continue
					}
					relPath := filepath.Join(subDir, sub.Name())
					b, err := reader.ReadFile(relPath)
					if err != nil {
						gaps.Add(nodeID, relPath, err)
						continue
					}
					if len(b) > 0 {
						out[relPath] = string(b)
					}
				}
				continue
			}
			ext := strings.ToLower(filepath.Ext(name))
			if ext != ".targets" && ext != ".props" {
				continue
			}
			relPath := filepath.Join(msbDir, name)
			b, err := reader.ReadFile(relPath)
			if err != nil {
				gaps.Add(nodeID, relPath, err)
				continue
			}
			if len(b) > 0 {
				out[relPath] = string(b)
			}
		}
	}
	return out
}

func applyHooks(g *graph.Graph, n *graph.Node, scripts, msbuildScripts map[string]string) {
	if len(scripts) > 0 {
		surface := installsurface.AnalyzeDotNet(scripts)
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
	if len(msbuildScripts) > 0 {
		surface := installsurface.AnalyzeMSBuild(msbuildScripts)
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
}

// scanDependencyPkg locates a dependency package's content in the NuGet global
// packages cache and scans it for install-time payloads. Hooks are attributed
// to the dependency node, not the project root.
func scanDependencyPkg(g *graph.Graph, n *graph.Node, pkgDirs []string, gaps *instsurf.Gaps) {
	if !isCleanPkgName(n.Name) || !isCleanPkgName(n.Version) {
		return
	}
	pkgDir := findNuGetPkgDir(pkgDirs, n.Name, n.Version)
	if pkgDir == "" {
		// Disclosed unconditionally (D-148). This used to be skipped when the
		// cache-dir list itself was empty (no NUGET_PACKAGES and no resolvable
		// home) — precisely the environment where NOTHING was examined, reported
		// as if everything had been. Fewer places to look is less coverage, not
		// less to say.
		gaps.AddReason(n.ID, n.Name+"@"+n.Version, instsurf.GapUnavailable, nil)
		return
	}
	pkgReader, err := securefs.NewReader(pkgDir)
	if err != nil {
		gaps.Add(n.ID, pkgDir, err)
		return
	}
	scripts := readPowerShellHooks(pkgReader, n.ID, gaps)
	msbuildScripts := scanMSBuildDirs(pkgReader, n.ID, gaps)
	applyHooks(g, n, scripts, msbuildScripts)
}

// nugetPackagesDirs returns the NuGet global packages cache directories to
// search, in priority order: NUGET_PACKAGES env var, then the default home
// location.
func nugetPackagesDirs() []string {
	var dirs []string
	if p := os.Getenv("NUGET_PACKAGES"); p != "" {
		dirs = append(dirs, p)
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".nuget", "packages"))
	}
	return dirs
}

// findNuGetPkgDir locates a NuGet package's extracted directory in the global
// packages cache. NuGet stores packages at <cache>/<lowercase-name>/<version>/.
func findNuGetPkgDir(dirs []string, name, version string) string {
	lower := strings.ToLower(name)
	for _, dir := range dirs {
		p := filepath.Join(dir, lower, version)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

// isCleanPkgName rejects names containing path separators or traversal
// components so they cannot steer directory lookups outside the cache.
func isCleanPkgName(s string) bool {
	return s != "" &&
		!strings.Contains(s, "/") &&
		!strings.Contains(s, "\\") &&
		!strings.Contains(s, "..")
}
