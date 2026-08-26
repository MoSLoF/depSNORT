package rubygems

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
// A gem with a native extension compiles it at install time by running
// extconf.rb — arbitrary Ruby, executed during `gem install`. A gem built via
// rake-compiler instead declares a `compile` Rake task that does the same
// thing under `rake compile`. This reads the root gem's extconf.rb (searched
// at the conventional locations), its gemspec, and its Rakefile from the
// on-disk checkout and analyzes them STATICALLY. Nothing is executed
// (Decision D-04).
//
// Dependency gems are analyzed too, when their source is locally present
// (D-148): Bundler's vendored path (vendor/bundle/ruby/*/gems) and an explicit
// $GEM_HOME are searched, the same local-only posture as Cargo's vendor/ and
// $CARGO_HOME lookup (D-140). A dependency found in neither is recorded as a
// source-unavailable coverage gap rather than silently skipped — before this,
// transitive gems were never examined AND never disclosed, so a Gemfile.lock
// full of native-extension gems scanned as if every extconf.rb had been read
// and found clean. A native extension is ordinary, so an extconf.rb without
// network/credential/obfuscation capability still produces no finding —
// false-positive discipline, not a miss.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)
	// Refused reads become typed gaps rather than looking like "no native
	// extension here" (R-01).
	var gaps instsurf.Gaps
	extconf := findExtconf(dir, "", &gaps)
	gemspec := readFirstGemspec(dir, "", &gaps)
	rakefile := findRakefile(dir, "", &gaps)
	// No early return when the ROOT has none of these. That return dated from
	// the root-only era and was harmless then; with dependency scanning it
	// would skip every dependency for exactly the most common project shape —
	// an application with a Gemfile.lock and no gemspec of its own (D-148).

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "gem" {
			continue
		}
		if !roots[n.ID] {
			scanDependencyGem(g, n, dir, &gaps)
			continue
		}
		surface := installsurface.AnalyzeRuby(extconf, gemspec, rakefile)
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
	return gaps.Err()
}

// scanDependencyGem analyzes one dependency gem's install surface from its
// locally installed source, or records that the source was unavailable.
func scanDependencyGem(g *graph.Graph, n *graph.Node, projectDir string, gaps *instsurf.Gaps) {
	if !isCleanGemName(n.Name) || !isCleanGemName(n.Version) {
		// A name or version that could steer the path join is a planted
		// signal, not a lookup key.
		gaps.AddReason(n.ID, n.Name+"@"+n.Version, instsurf.GapContainment, nil)
		return
	}
	gemDir := findGemDir(projectDir, n.Name, n.Version)
	if gemDir == "" {
		gaps.AddReason(n.ID, n.Name+"@"+n.Version, instsurf.GapUnavailable, nil)
		return
	}
	extconf := findExtconf(gemDir, n.ID, gaps)
	gemspec := readFirstGemspec(gemDir, n.ID, gaps)
	rakefile := findRakefile(gemDir, n.ID, gaps)
	surface := installsurface.AnalyzeRuby(extconf, gemspec, rakefile)
	if len(surface.Hooks) > 0 {
		instsurf.AddToGraph(g, n, surface)
	}
}

// gemParentDirs returns the directories under which installed gems live as
// gems/<name>-<version>, in priority order: the project's own Bundler vendor
// path (any ruby version), then an explicit $GEM_HOME. Both are local-only —
// nothing is fetched (D-04); a gem in neither place is disclosed, not chased.
func gemParentDirs(projectDir string) []string {
	var out []string
	vendored, _ := filepath.Glob(filepath.Join(projectDir, "vendor", "bundle", "ruby", "*", "gems"))
	out = append(out, vendored...)
	if gh := os.Getenv("GEM_HOME"); gh != "" {
		out = append(out, filepath.Join(gh, "gems"))
	}
	return out
}

// findGemDir locates an installed gem's source directory (gems/<name>-<version>).
func findGemDir(projectDir, name, version string) string {
	for _, parent := range gemParentDirs(projectDir) {
		p := filepath.Join(parent, name+"-"+version)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

// isCleanGemName rejects lookup keys containing separators or traversal so a
// crafted Gemfile.lock entry cannot walk the join out of the gem directories.
func isCleanGemName(s string) bool {
	return s != "" &&
		!strings.Contains(s, "/") &&
		!strings.Contains(s, "\\") &&
		!strings.Contains(s, "..")
}

// findExtconf looks for extconf.rb at the gem root and under ext/ (the
// conventional home for native-extension build scripts), bounded to a shallow
// walk so a large repo is not traversed wholesale.
func findExtconf(dir, pkgID string, gaps *instsurf.Gaps) string {
	// Contained reads (F-03): a build script symlinked out of the gem is refused.
	reader, err := securefs.NewReader(dir)
	if err != nil {
		gaps.Add(pkgID, dir, err)
		return ""
	}
	read := func(rel string) (string, bool) {
		b, err := reader.ReadFile(rel)
		if err != nil {
			gaps.Add(pkgID, filepath.Join(dir, rel), err)
			return "", false
		}
		return string(b), len(b) > 0
	}
	for _, c := range []string{"extconf.rb", filepath.Join("ext", "extconf.rb")} {
		if s, ok := read(c); ok {
			return s
		}
	}
	// ext/<name>/extconf.rb — one directory level under ext/.
	//
	// Enumeration is containment-checked BEFORE listing (R-03 P2): if ext/ is a
	// symlink pointing out of the gem, the per-file reads below would each be
	// refused anyway, but we would still have enumerated an out-of-tree
	// directory's names and leaked them into gap paths. Refuse up front instead.
	extRoot := filepath.Join(dir, "ext")
	// Only an ext/ that EXISTS but is not contained is a refusal. Most gems ship
	// no ext/ at all, and treating that absence as a gap would gate every clean
	// Ruby project — the same absence-vs-refusal distinction R-01 turns on.
	if _, statErr := os.Lstat(extRoot); statErr == nil && !reader.Contains(extRoot) {
		gaps.AddReason(pkgID, extRoot, instsurf.GapContainment, nil)
		return ""
	}
	if entries, err := os.ReadDir(extRoot); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if s, ok := read(filepath.Join("ext", e.Name(), "extconf.rb")); ok {
				return s
			}
		}
	}
	return ""
}

// findRakefile looks for a Rakefile at the gem root — the conventional home
// for a rake-compiler native-extension "compile" task. Root-gem scope only
// (same documented limitation as extconf.rb — transitive gems aren't on
// disk).
func findRakefile(dir, pkgID string, gaps *instsurf.Gaps) string {
	// Contained reads (F-03): a Rakefile symlinked out of the gem is refused.
	reader, err := securefs.NewReader(dir)
	if err != nil {
		gaps.Add(pkgID, dir, err)
		return ""
	}
	read := func(rel string) (string, bool) {
		b, err := reader.ReadFile(rel)
		if err != nil {
			gaps.Add(pkgID, filepath.Join(dir, rel), err)
			return "", false
		}
		return string(b), len(b) > 0
	}
	for _, c := range []string{"Rakefile", "rakefile"} {
		if s, ok := read(c); ok {
			return s
		}
	}
	return ""
}

// readFirstGemspec returns the contents of the first *.gemspec in dir.
func readFirstGemspec(dir, pkgID string, gaps *instsurf.Gaps) string {
	reader, err := securefs.NewReader(dir)
	if err != nil {
		gaps.Add(pkgID, dir, err)
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".gemspec" {
			continue
		}
		b, err := reader.ReadFile(e.Name())
		if err != nil {
			// The gemspec is listed in the directory, so it exists; being
			// unable to read it is a gap, not an absence.
			gaps.Add(pkgID, filepath.Join(dir, e.Name()), err)
			continue
		}
		return string(b)
	}
	return ""
}
