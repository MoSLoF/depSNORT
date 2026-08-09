package cargo

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
// A Cargo crate's install-time execution lives in build.rs, which runs at
// compile time with the full privileges of the build. This reads the root
// crate's build.rs from the on-disk checkout and analyzes it STATICALLY —
// nothing is executed (Decision D-04).
//
// Scope is the root crate only. Transitive crates resolve from crates.io and
// are not on disk in a source checkout, so — exactly as the npm and pypi
// adapters do — their build scripts are not available to read and are left
// unrepresented rather than guessed at. A build.rs is ordinary in Rust, so a
// build script with no network/credential/obfuscation capability produces no
// finding; that is the false-positive discipline, not a miss.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)
	buildRs, err := os.ReadFile(filepath.Join(dir, "build.rs"))
	if err != nil || len(buildRs) == 0 {
		return nil // no build script on disk; nothing to extract
	}

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "cargo" || !roots[n.ID] {
			continue
		}
		surface := installsurface.AnalyzeRust(string(buildRs))
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
	return nil
}
