package pypi

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestParsePyprojectPEP621(t *testing.T) {
	raw := []byte(`[build-system]
requires = ["setuptools>=61.0"]

[project]
name = "pyrsistencesniper"
version = "0.5.0"
dependencies = [
    "libregf-python (>=20240303,<20280000)",
    "pyyaml (>=6.0.3,<7.0.0)",
    "jinja2 (>=3.1.6,<4.0.0)",
]
`)
	if !pyprojectDeclaresDeps2(raw) {
		t.Fatal("PEP 621 deps not detected")
	}
	g, err := parsePyproject("/repo/pyrsistencesniper/pyproject.toml", raw)
	if err != nil {
		t.Fatal(err)
	}
	root := g.Get(g.Roots[0])
	dd := root.DeclaredDepsOf()
	got := map[string]string{}
	for _, d := range dd {
		got[d.Name] = d.Constraint
	}
	if got["pyyaml"] != ">=6.0.3,<7.0.0" {
		t.Errorf("pyyaml constraint = %q, want >=6.0.3,<7.0.0", got["pyyaml"])
	}
	if got["libregf-python"] != ">=20240303,<20280000" {
		t.Errorf("libregf-python constraint = %q", got["libregf-python"])
	}
	if len(dd) != 3 {
		t.Errorf("declared deps = %d, want 3", len(dd))
	}
}

func TestParsePyprojectPoetry(t *testing.T) {
	raw := []byte(`[tool.poetry]
name = "app"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
click = ">=8.0,<9.0"
rich = { version = "^13.0", optional = true }
`)
	g, err := parsePyproject("/repo/app/pyproject.toml", raw)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range g.Get(g.Roots[0]).DeclaredDepsOf() {
		got[d.Name] = d.Constraint
	}
	if _, ok := got["python"]; ok {
		t.Error("python (the interpreter) must not be a package dependency")
	}
	if got["requests"] != "^2.31" {
		t.Errorf("requests = %q, want ^2.31", got["requests"])
	}
	if got["rich"] != "^13.0" {
		t.Errorf("rich (inline table) = %q, want ^13.0", got["rich"])
	}
}

func TestPyprojectWithNoDepsIsNotAProject(t *testing.T) {
	raw := []byte(`[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "tool-only"
version = "1.0"
`)
	if pyprojectDeclaresDeps2(raw) {
		t.Error("a pyproject with no dependencies must not be claimed as a resolvable project")
	}
}

// pyprojectDeclaresDeps2 is the byte-level variant for tests (the real one reads
// a path).
func pyprojectDeclaresDeps2(raw []byte) bool {
	d, _ := parsePyprojectDeps(raw)
	return len(d) > 0
}

func TestDeclaredDepsRoundTrip(t *testing.T) {
	in := []graph.DeclaredDep{{Name: "a", Constraint: ">=1.0"}, {Name: "b", Constraint: ""}}
	out := graph.DecodeDeclaredDeps(graph.EncodeDeclaredDeps(in))
	if len(out) != 2 || out[0] != in[0] || out[1] != in[1] {
		t.Errorf("round trip: %v -> %v", in, out)
	}
	if strings.Contains(graph.EncodeDeclaredDeps(in), "\t\t") {
		t.Error("encoding malformed")
	}
}
