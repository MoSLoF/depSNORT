package gomod

import (
	"testing"

	"ihbv.io/depsnort/internal/purl"
)

func TestParseGoMod(t *testing.T) {
	raw := []byte(`module github.com/sipeed/picoclaw

go 1.25.7

require (
	github.com/google/uuid v1.6.0
	github.com/openai/openai-go/v3 v3.22.0
	golang.org/x/oauth2 v0.35.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require github.com/single/dep v2.0.0+incompatible
`)
	g, err := parseGoMod("/repo/picoclaw/go.mod", raw)
	if err != nil {
		t.Fatal(err)
	}
	root := g.Get(g.Roots[0])
	if root.Name != "github.com/sipeed/picoclaw" {
		t.Errorf("module = %q", root.Name)
	}
	// direct dep
	uuid := g.Get(purl.NewGo("github.com/google/uuid", "v1.6.0").String())
	if uuid == nil || !uuid.Direct {
		t.Errorf("uuid direct node missing/wrong: %+v", uuid)
	}
	// indirect dep
	spew := g.Get(purl.NewGo("github.com/davecgh/go-spew", "v1.1.1").String())
	if spew == nil || spew.Direct {
		t.Errorf("go-spew should be indirect (Direct=false): %+v", spew)
	}
	// major-version suffix kept in the path
	if g.Get(purl.NewGo("github.com/openai/openai-go/v3", "v3.22.0").String()) == nil {
		t.Error("major-version-suffixed module missing")
	}
	// +incompatible tolerated
	if g.Get(purl.NewGo("github.com/single/dep", "v2.0.0+incompatible").String()) == nil {
		t.Error("single-line require with +incompatible missing")
	}
	// flat resolution disclosed
	if root.Attr["depsnort.flat_resolution"] != "gomod" {
		t.Error("go.mod flat resolution not disclosed")
	}
	// the `go` directive is recorded on the root so the report layer can decide
	// the OPU-15 module-graph-pruning disclosure without re-reading go.mod.
	if root.Attr[AttrGoDirective] != "1.25.7" {
		t.Errorf("go directive attr = %q, want 1.25.7", root.Attr[AttrGoDirective])
	}
	// count: root + 6 requires
	pk := 0
	for _, n := range g.SortedNodes() {
		if n.Kind == "" || n.Kind == "package" {
			pk++
		}
	}
	if pk != 7 {
		t.Errorf("nodes = %d, want 7 (root + 6)", pk)
	}
}

func TestDetect(t *testing.T) {
	if (&Adapter{}).Name() != "gomod" {
		t.Error("name")
	}
}

// TestGoDirectivePruning locks in the OPU-15 mitigation gate: HasPrunedModuleGraph
// (via goDirectiveAtLeast) must fire for go 1.17+ and stay quiet below it, and must
// treat a malformed or absent directive as pre-1.17 (never wrongly claim pruning).
func TestGoDirectivePruning(t *testing.T) {
	cases := []struct {
		directive string
		pruned    bool
	}{
		{"1.25.0", true},  // opensnitch's real case
		{"1.25", true},    // two-component form
		{"1.18", true},    // xray
		{"1.17", true},    // the boundary — pruning starts here
		{"1.16", false},   // shellz — must stay exact, no pruning
		{"1.9", false},    // old two-component
		{"1.16.5", false}, // three-component below boundary
		{"", false},       // absent → conservative, treat as unpruned
		{"notaversion", false},
		{"1", false},   // single component, unparseable minor
		{"1.x", false}, // malformed minor
	}
	for _, c := range cases {
		if got := HasPrunedModuleGraph(c.directive); got != c.pruned {
			t.Errorf("HasPrunedModuleGraph(%q) = %v, want %v", c.directive, got, c.pruned)
		}
	}
}

// TestGoDirectiveExtraction confirms scanGoMod reads the `go` line out of go.mod
// text (single- and multi-digit minors) and returns "" when there is none — the
// input that makes the disclosure conservatively silent and drives pruning.
func TestGoDirectiveExtraction(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"present", "module x\n\ngo 1.25.0\n\nrequire y v1.0.0\n", "1.25.0"},
		{"two-component", "module x\ngo 1.16\n", "1.16"},
		{"absent", "module x\nrequire y v1.0.0\n", ""},
		{"leading-space", "module x\n  go 1.21 \n", "1.21"},
	}
	for _, c := range cases {
		if _, got, _ := scanGoMod([]byte(c.raw)); got != c.want {
			t.Errorf("%s: scanGoMod goVersion = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestParseGoModPre117NoDirectiveGate is the silent-path companion to
// TestParseGoMod: a go 1.16 main records its directive but must NOT be flagged for
// the pruning disclosure (pruning does not apply pre-1.17).
func TestParseGoModPre117NoDirectiveGate(t *testing.T) {
	g, err := parseGoMod("/repo/legacy/go.mod", []byte("module example.com/legacy\n\ngo 1.16\n\nrequire golang.org/x/net v0.48.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	root := g.Get(g.Roots[0])
	if root.Attr[AttrGoDirective] != "1.16" {
		t.Errorf("go directive attr = %q, want 1.16", root.Attr[AttrGoDirective])
	}
	if HasPrunedModuleGraph(root.Attr[AttrGoDirective]) {
		t.Error("go 1.16 main must not be flagged for the pruning disclosure")
	}
}
