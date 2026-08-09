package nuget

import (
	"os"
	"path/filepath"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// ExtractInstallSurface implements ecosystem.InstallSurfaceExtractor (Decision
// D-26).
//
// A NuGet package can ship PowerShell that runs on install (install.ps1) or
// when the solution opens (init.ps1). This reads those scripts from the root
// package directory and analyzes them STATICALLY. Nothing is executed
// (Decision D-04).
//
// Scope is the root package directory: transitive packages resolve from the
// NuGet gallery and are not on disk in a source checkout. A script with no
// network/credential/obfuscation capability produces no finding.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)

	scripts := map[string]string{}
	for _, name := range installsurface.NuGetInstallHookNames {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil && len(b) > 0 {
			scripts[name] = string(b)
		}
	}
	if len(scripts) == 0 {
		return nil
	}

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "nuget" || !roots[n.ID] {
			continue
		}
		surface := installsurface.AnalyzeDotNet(scripts)
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
	return nil
}
