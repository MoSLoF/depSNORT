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

// OPU-10: a PEP 621 dependency carrying an extras bracket ("pkg[extra]...") must
// not break array parsing. The extras '[' / ']' are inside the quoted string and
// must be treated as content, not as array structure. Before the fix the naive
// first-']' bound collapsed the array to empty, so an extras-bearing project read
// as "no dependencies" and was silently skipped.
func TestParsePyprojectExtrasDependencies(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want map[string]string // dep name -> constraint (extras already stripped)
	}{
		{
			name: "single extras dep, single-line array",
			toml: "[project]\nname = \"x\"\ndependencies = [\"requests[security]>=2.0\"]\n",
			want: map[string]string{"requests": ">=2.0"},
		},
		{
			name: "extras mixed with plain, multi-line array",
			toml: "[project]\nname = \"x\"\ndependencies = [\n  \"flask>=2.0\",\n  \"uvicorn[standard]>=0.20\",\n  \"celery[redis,auth]>=5\",\n]\n",
			want: map[string]string{"flask": ">=2.0", "uvicorn": ">=0.20", "celery": ">=5"},
		},
		{
			// The exact PurpleCrew shape: an extras-only sole dependency.
			name: "extras-only sole dependency",
			toml: "[project]\nname = \"x\"\ndependencies = [\"crewai[tools]>=0.100.1,<1.0.0\"]\n",
			want: map[string]string{"crewai": ">=0.100.1,<1.0.0"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := []byte(c.toml)
			if !pyprojectDeclaresDeps2(raw) {
				t.Fatal("extras-bearing pyproject must be claimed as a project")
			}
			g, err := parsePyproject("/repo/x/pyproject.toml", raw)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, d := range g.Get(g.Roots[0]).DeclaredDepsOf() {
				got[d.Name] = d.Constraint
			}
			if len(got) != len(c.want) {
				t.Fatalf("declared deps = %v, want %v", got, c.want)
			}
			for name, want := range c.want {
				if got[name] != want {
					t.Errorf("%s constraint = %q, want %q", name, got[name], want)
				}
			}
		})
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

// TestParsePyprojectArrayComments locks in OPU-11: a `#` comment inside the
// multi-line dependencies array must not contribute phantom dependencies, even
// when it contains quoted words — while a `#` inside a quoted requirement (a
// URL egg fragment) must be preserved. quotedItems harvests every quoted token,
// so without comment stripping `"clean"` in a comment became a fake dep.
func TestParsePyprojectArrayComments(t *testing.T) {
	raw := []byte(`[project]
name = "soup"
dependencies = [
    "rich>=13.0.0",
    # a silent "clean" without it — the wrong direction for a checker
    "typer>=0.9.0",  # trailing "phantompkg" note must not leak
    "somepkg @ git+https://example.com/x.git#egg=somepkg",
]
`)
	g, err := parsePyproject("/repo/soup/pyproject.toml", raw)
	if err != nil {
		t.Fatal(err)
	}
	root := g.Get(g.Roots[0])
	got := map[string]bool{}
	for _, d := range root.DeclaredDepsOf() {
		got[d.Name] = true
	}
	for _, phantom := range []string{"clean", "phantompkg"} {
		if got[phantom] {
			t.Errorf("phantom dependency %q scraped from a comment", phantom)
		}
	}
	for _, real := range []string{"rich", "typer", "somepkg"} {
		if !got[real] {
			t.Errorf("real dependency %q missing (comment stripping over-reached)", real)
		}
	}
	if n := len(root.DeclaredDepsOf()); n != 3 {
		t.Errorf("declared deps = %d, want 3 (rich, typer, somepkg)", n)
	}
}

// TestParsePyprojectExtras locks in OPU-12 D-1: [project.optional-dependencies]
// is parsed into the union of every extra's deps; a self-referential meta-extra
// (soup-cli[all], soup-cli[train,mlx]) expands to local extras WITHOUT emitting
// the project's own name as an external dependency; and a cross-extra pin split
// (transformers <5 in train, >=5 in mlx) collapses to one deduped node — never
// two conflicting constraints that would be mis-reported as contested.
func TestParsePyprojectExtras(t *testing.T) {
	raw := []byte(`[project]
name = "soup-cli"
dependencies = [
    "rich>=13.0.0",
    "typer<0.21.0",
]

[project.optional-dependencies]
train = [
    "torch>=2.0",
    "transformers<5.0.0",  # train wants the pre-5 line
    "trl<0.29",
]
mlx = [
    "mlx-lm",
    "transformers>=5.0.0",  # mlx wants 5+ — a mutually exclusive profile
]
dev = [
    "soup-cli[all]",  # self-referential meta-extra
    "pytest>=7",
    "ruff",
]
all = [
    "soup-cli[train,mlx]",
]
`)
	g, err := parsePyproject("/repo/soup/pyproject.toml", raw)
	if err != nil {
		t.Fatal(err)
	}
	root := g.Get(g.Roots[0])
	got := map[string]string{}
	for _, d := range root.DeclaredDepsOf() {
		got[d.Name] = d.Constraint
	}

	// The project's OWN name must never be emitted (dependency-confusion FP).
	if _, ok := got["soup-cli"]; ok {
		t.Error("self-reference leaked the project's own name as a dependency")
	}
	// Union of core + every extra's deps, deduped by name.
	want := []string{"rich", "typer", "torch", "transformers", "trl", "mlx-lm", "pytest", "ruff"}
	for _, name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("declared dep %q missing (extras not unioned?)", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("declared deps = %d %v, want %d", len(got), got, len(want))
	}
	// Cross-extra pin split: transformers is ONE node with ONE constraint (the
	// sorted-first extra, mlx), not two conflicting constraints → no contested.
	if got["transformers"] != ">=5.0.0" {
		t.Errorf("transformers constraint = %q, want >=5.0.0 (deterministic sorted-first extra)", got["transformers"])
	}
}
