package cargo

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
// A Cargo crate's install-time execution lives in:
//   - build.rs: a build script that runs at compile time with full privileges.
//   - proc-macro crates: compile-time code generation that executes arbitrary
//     Rust when a dependent crate is compiled.
//
// Two scopes are checked:
//
//  1. The root crate — its build.rs and Cargo.toml are read from the on-disk
//     checkout (existing behavior).
//  2. Each dependency crate — when vendored source or the Cargo registry cache
//     is available, each dependency's Cargo.toml is checked for proc-macro
//     status and its build.rs and src/lib.rs are analyzed. Hooks are attributed
//     to the DEPENDENCY PURL, not the root.
//
// Everything is analyzed STATICALLY — nothing is executed (Decision D-04).
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

	// ---- root crate scan ----

	buildRs, err := reader.ReadFile("build.rs")
	if err != nil {
		gaps.Add("", filepath.Join(dir, "build.rs"), err)
	}

	cargoToml, err := reader.ReadFile("Cargo.toml")
	if err != nil {
		gaps.Add("", filepath.Join(dir, "Cargo.toml"), err)
	}

	hasBuildRs := len(buildRs) > 0
	rootIsProcMacro := isProcMacroCrate(string(cargoToml))

	var procMacroSource string
	if rootIsProcMacro {
		if b, err := reader.ReadFile(filepath.Join("src", "lib.rs")); err == nil {
			procMacroSource = string(b)
		} else {
			gaps.Add("", filepath.Join(dir, "src", "lib.rs"), err)
		}
	}

	if hasBuildRs || rootIsProcMacro {
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
			if rootIsProcMacro {
				surface := installsurface.AnalyzeProcMacro(procMacroSource)
				if len(surface.Hooks) > 0 {
					instsurf.AddToGraph(g, n, surface)
				}
			}
		}
	}

	// ---- dependency crate scan ----
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "cargo" || roots[n.ID] {
			continue
		}
		scanCargoDependency(g, n, dir, &gaps)
	}

	return gaps.Err()
}

// scanCargoDependency checks a dependency crate's vendored or cached source
// for build.rs and proc-macro status, attributing hooks to the dependency node.
func scanCargoDependency(g *graph.Graph, n *graph.Node, projectDir string, gaps *instsurf.Gaps) {
	if !isCleanCrateName(n.Name) || !isCleanCrateName(n.Version) {
		return
	}
	depDir := findCargoDependencyDir(projectDir, n.Name, n.Version)
	if depDir == "" {
		return
	}
	depReader, err := securefs.NewReader(depDir)
	if err != nil {
		gaps.Add(n.ID, depDir, err)
		return
	}

	cargoToml, err := depReader.ReadFile("Cargo.toml")
	if err != nil {
		gaps.Add(n.ID, filepath.Join(depDir, "Cargo.toml"), err)
		return
	}

	buildRs, buildErr := depReader.ReadFile("build.rs")
	if buildErr != nil {
		gaps.Add(n.ID, filepath.Join(depDir, "build.rs"), buildErr)
	}
	if len(buildRs) > 0 {
		surface := installsurface.AnalyzeRust(string(buildRs))
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}

	if isProcMacroCrate(string(cargoToml)) {
		var source string
		if b, err := depReader.ReadFile(filepath.Join("src", "lib.rs")); err == nil {
			source = string(b)
		} else {
			gaps.Add(n.ID, filepath.Join(depDir, "src", "lib.rs"), err)
		}
		surface := installsurface.AnalyzeProcMacro(source)
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
}

// findCargoDependencyDir locates a dependency crate's source directory.
// It checks, in order:
//  1. vendor/<name>/ (Cargo vendor output, inside project)
//  2. CARGO_HOME/registry/src/<index>/<name>-<version>/ (registry cache)
func findCargoDependencyDir(projectDir, name, version string) string {
	vendorDir := filepath.Join(projectDir, "vendor", name)
	if info, err := os.Stat(vendorDir); err == nil && info.IsDir() {
		return vendorDir
	}

	cargoHome := os.Getenv("CARGO_HOME")
	if cargoHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cargoHome = filepath.Join(home, ".cargo")
		}
	}
	if cargoHome != "" {
		registrySrc := filepath.Join(cargoHome, "registry", "src")
		entries, err := os.ReadDir(registrySrc)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					crateDir := filepath.Join(registrySrc, entry.Name(), name+"-"+version)
					if info, err := os.Stat(crateDir); err == nil && info.IsDir() {
						return crateDir
					}
				}
			}
		}
	}
	return ""
}

// isCleanCrateName rejects names containing path separators or traversal
// components so they cannot steer directory lookups outside vendor/.
func isCleanCrateName(s string) bool {
	return s != "" &&
		!strings.Contains(s, "/") &&
		!strings.Contains(s, "\\") &&
		!strings.Contains(s, "..")
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
