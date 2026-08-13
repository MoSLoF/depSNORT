package nuget

import (
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
//   - MSBuild .targets/.props files in build/ or buildTransitive/ that execute
//     arbitrary targets at build time.
//
// This reads those files from the root package directory and analyzes them
// STATICALLY. Nothing is executed (Decision D-04).
//
// Scope is the root package directory: transitive packages resolve from the
// NuGet gallery and are not on disk in a source checkout. A script with no
// network/credential/obfuscation capability produces no finding.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)

	reader, err := securefs.NewReader(dir)
	if err != nil {
		return err
	}
	var gaps instsurf.Gaps

	// PowerShell install hooks.
	scripts := map[string]string{}
	for _, name := range installsurface.NuGetInstallHookNames {
		b, err := reader.ReadFile(name)
		if err != nil {
			gaps.Add("", name, err)
			continue
		}
		if len(b) > 0 {
			scripts[name] = string(b)
		}
	}

	// MSBuild .targets/.props from build/ and buildTransitive/.
	msbuildScripts := map[string]string{}
	for _, msbDir := range installsurface.NuGetMSBuildDirs {
		entries, err := reader.ReadDir(msbDir)
		if err != nil {
			gaps.Add("", msbDir, err)
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			ext := strings.ToLower(filepath.Ext(name))
			if ext != ".targets" && ext != ".props" {
				continue
			}
			relPath := filepath.Join(msbDir, name)
			b, err := reader.ReadFile(relPath)
			if err != nil {
				gaps.Add("", relPath, err)
				continue
			}
			if len(b) > 0 {
				msbuildScripts[relPath] = string(b)
			}
		}
	}

	if len(scripts) == 0 && len(msbuildScripts) == 0 {
		return gaps.Err()
	}

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "nuget" || !roots[n.ID] {
			continue
		}
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
	return gaps.Err()
}
