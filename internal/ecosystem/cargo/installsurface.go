package cargo

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
// A Cargo crate's install-time execution lives in:
//   - build.rs: a build script that runs at compile time with full privileges.
//   - proc-macro crates: compile-time code generation that executes arbitrary
//     Rust when a dependent crate is compiled.
//
// This reads the root crate's build.rs and Cargo.toml from the on-disk
// checkout and analyzes them STATICALLY — nothing is executed (Decision D-04).
//
// Scope is the root crate only. Transitive crates resolve from crates.io and
// are not on disk in a source checkout, so their build scripts are not
// available to read and are left unrepresented rather than guessed at.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)
	reader, err := securefs.NewReader(dir)
	if err != nil {
		return err
	}
	var gaps instsurf.Gaps

	// build.rs analysis.
	buildRs, err := reader.ReadFile("build.rs")
	if err != nil {
		gaps.Add("", filepath.Join(dir, "build.rs"), err)
	}

	// Cargo.toml proc-macro detection.
	cargoToml, err := reader.ReadFile("Cargo.toml")
	if err != nil {
		gaps.Add("", filepath.Join(dir, "Cargo.toml"), err)
	}

	hasBuildRs := len(buildRs) > 0
	isProcMacro := isProcMacroCrate(string(cargoToml))

	// Read the proc-macro's source when available so its capabilities
	// flow through the VC-002 family.
	var procMacroSource string
	if isProcMacro {
		if b, err := reader.ReadFile(filepath.Join("src", "lib.rs")); err == nil {
			procMacroSource = string(b)
		} else {
			gaps.Add("", filepath.Join(dir, "src", "lib.rs"), err)
		}
	}

	if !hasBuildRs && !isProcMacro {
		return gaps.Err()
	}

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "cargo" || !roots[n.ID] {
			continue
		}
		if hasBuildRs {
			surface := installsurface.AnalyzeRust(string(buildRs))
			if len(surface.Hooks) > 0 {
				instsurf.AddToGraph(g, n, surface)
			}
		}
		if isProcMacro {
			surface := installsurface.AnalyzeProcMacro(procMacroSource)
			if len(surface.Hooks) > 0 {
				instsurf.AddToGraph(g, n, surface)
			}
		}
	}
	return gaps.Err()
}

// isProcMacroCrate checks whether Cargo.toml declares this crate as a
// proc-macro. The declaration is `proc-macro = true` under `[lib]`.
func isProcMacroCrate(toml string) bool {
	inLib := false
	for _, line := range strings.Split(toml, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[lib]" {
			inLib = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inLib = false
			continue
		}
		if inLib {
			noSpaces := strings.ReplaceAll(trimmed, " ", "")
			if noSpaces == "proc-macro=true" || noSpaces == "proc_macro=true" {
				return true
			}
		}
	}
	return false
}
