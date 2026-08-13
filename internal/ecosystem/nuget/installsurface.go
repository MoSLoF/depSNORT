package nuget

import (
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/securefs"
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

	// Contained reads (F-03): an install.ps1 symlinked out of the package tree
	// is refused rather than followed off-disk.
	reader, err := securefs.NewReader(dir)
	if err != nil {
		return err
	}
	// A refused install.ps1 is a gap, not an absence (R-01).
	var gaps instsurf.Gaps
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
	if len(scripts) == 0 {
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
		surface := installsurface.AnalyzeDotNet(scripts)
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
	return gaps.Err()
}
