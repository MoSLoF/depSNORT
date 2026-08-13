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
		scanCargoDependency(g, n, dir, reader, &gaps)
	}

	return gaps.Err()
}

// scanCargoDependency checks a dependency crate's vendored or cached source
// for build.rs and proc-macro status, attributing hooks to the dependency node.
func scanCargoDependency(g *graph.Graph, n *graph.Node, projectDir string, projectReader *securefs.Reader, gaps *instsurf.Gaps) {
	if !isCleanCrateName(n.Name) || !isCleanCrateName(n.Version) {
		return
	}
	depDir, _ := findCargoDependencyDir(projectDir, projectReader, n.Name, n.Version, gaps, n.ID)
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

type vendorCandidate struct {
	dir string // absolute path
	rel string // relative to projectDir (for containment check)
}

// findCargoDependencyDir locates a dependency crate's source directory and
// validates its manifest identity. It checks, in order:
//
//  1. vendor/<name>/ and vendor/<name>-<version>/ — both are enumerated, each
//     candidate's Cargo.toml is parsed, and only a manifest whose [package]
//     name and version match the requested dependency is accepted. When both
//     exist and match, the versioned directory wins (it is unambiguous).
//  2. CARGO_HOME/registry/src/<index>/<name>-<version>/ — registry cache,
//     already version-qualified by directory name.
//
// Returns (absoluteDir, vendorRelative). vendorRelative is non-empty for
// vendor/ hits (subject to containment checks). Emits typed gaps for identity
// mismatches and unavailable source directly.
func findCargoDependencyDir(projectDir string, projectReader *securefs.Reader, name, version string, gaps *instsurf.Gaps, nodeID string) (string, string) {
	candidates := []vendorCandidate{}
	for _, sub := range []string{name, name + "-" + version} {
		rel := filepath.Join("vendor", sub)
		full := filepath.Join(projectDir, rel)
		if info, err := os.Stat(full); err == nil && info.IsDir() {
			candidates = append(candidates, vendorCandidate{dir: full, rel: rel})
		}
	}

	var matched []vendorCandidate
	for _, c := range candidates {
		if !projectReader.Contains(c.rel) {
			gaps.Add(nodeID, c.rel, securefs.ErrOutsideRoot)
			continue
		}
		tomlPath := filepath.Join(c.dir, "Cargo.toml")
		b, err := os.ReadFile(tomlPath)
		if err != nil {
			gaps.Add(nodeID, tomlPath, err)
			continue
		}
		mName, mVersion := extractManifestIdentity(string(b))
		if mName == name && mVersion == version {
			matched = append(matched, c)
		} else {
			gaps.AddReason(nodeID, c.rel, instsurf.GapIdentityMismatch, nil)
		}
	}

	if len(matched) > 0 {
		best := matched[0]
		for _, c := range matched[1:] {
			if strings.HasSuffix(filepath.Base(c.rel), "-"+version) {
				best = c
			}
		}
		return best.dir, best.rel
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
						return crateDir, ""
					}
				}
			}
		}
	}

	if len(candidates) == 0 {
		gaps.AddReason(nodeID, name+"@"+version, instsurf.GapUnavailable, nil)
	}
	return "", ""
}

// extractManifestIdentity reads the [package] name and version from a
// Cargo.toml without a full TOML parser.
func extractManifestIdentity(toml string) (string, string) {
	var name, version string
	inPackage := false
	for _, line := range strings.Split(toml, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[package]" {
			inPackage = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
		switch key {
		case "name":
			name = extractTOMLString(trimmed)
		case "version":
			version = extractTOMLString(trimmed)
		}
	}
	return name, version
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
