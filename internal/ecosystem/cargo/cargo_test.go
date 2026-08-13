package cargo

import (
	"testing"

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

func TestNonProcMacroCrateNoHook(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "proc-macro" {
			t.Error("non-proc-macro crate should not generate a proc-macro hook node")
		}
	}
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
