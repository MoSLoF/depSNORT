package cargo

import (
	"path/filepath"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/securefs"
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
	// Contained read (F-03): a build.rs symlinked out of the crate is refused.
	reader, err := securefs.NewReader(dir)
	if err != nil {
		return err
	}
	buildRs, err := reader.ReadFile("build.rs")
	if err != nil {
		// Absent is the common case (most crates have no build script); a
		// refusal means one exists and was hidden from us (R-01).
		var gaps instsurf.Gaps
		gaps.Add("", filepath.Join(dir, "build.rs"), err)
		return gaps.Err()
	}
	if len(buildRs) == 0 {
		return nil
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
