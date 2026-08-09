package rubygems

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
// A gem with a native extension compiles it at install time by running
// extconf.rb — arbitrary Ruby, executed during `gem install`. This reads the
// root gem's extconf.rb (searched at the conventional locations) and its
// gemspec from the on-disk checkout and analyzes them STATICALLY. Nothing is
// executed (Decision D-04).
//
// Scope is the root gem only: transitive gems are fetched from rubygems.org and
// are not present in a source checkout. A native extension is ordinary, so an
// extconf.rb without network/credential/obfuscation capability produces no
// finding — false-positive discipline, not a miss.
func (*Adapter) ExtractInstallSurface(path string, g *graph.Graph) error {
	dir := instsurf.ProjectDir(path)
	extconf := findExtconf(dir)
	gemspec := readFirstGemspec(dir)
	if extconf == "" && gemspec == "" {
		return nil
	}

	roots := map[string]bool{}
	for _, r := range g.Roots {
		roots[r] = true
	}
	for _, n := range g.SortedNodes() {
		if n.Kind != graph.KindPackage || n.Ecosystem != "gem" || !roots[n.ID] {
			continue
		}
		surface := installsurface.AnalyzeRuby(extconf, gemspec)
		if len(surface.Hooks) > 0 {
			instsurf.AddToGraph(g, n, surface)
		}
	}
	return nil
}

// findExtconf looks for extconf.rb at the gem root and under ext/ (the
// conventional home for native-extension build scripts), bounded to a shallow
// walk so a large repo is not traversed wholesale.
func findExtconf(dir string) string {
	candidates := []string{
		filepath.Join(dir, "extconf.rb"),
		filepath.Join(dir, "ext", "extconf.rb"),
	}
	for _, c := range candidates {
		if b, err := os.ReadFile(c); err == nil && len(b) > 0 {
			return string(b)
		}
	}
	// ext/<name>/extconf.rb — one directory level under ext/.
	extRoot := filepath.Join(dir, "ext")
	if entries, err := os.ReadDir(extRoot); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(extRoot, e.Name(), "extconf.rb")); err == nil && len(b) > 0 {
				return string(b)
			}
		}
	}
	return ""
}

// readFirstGemspec returns the contents of the first *.gemspec in dir.
func readFirstGemspec(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".gemspec" {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			return string(b)
		}
	}
	return ""
}
