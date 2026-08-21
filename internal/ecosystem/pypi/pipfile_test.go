package pypi

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

const samplePipfile = `[[source]]
url = "https://pypi.org/simple"
name = "pypi"
verify_ssl = true

[packages]
requests = "*"
flask = {version = ">=2.0", extras = ["async"]}
django = ">=4.0,<5"

[dev-packages]
pytest = "*"

[requires]
python_version = "3.11"
`

func TestParsePipfile(t *testing.T) {
	g, err := parsePipfile("proj/Pipfile", []byte(samplePipfile))
	if err != nil {
		t.Fatalf("parsePipfile: %v", err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want one", g.Roots)
	}
	root := g.Get(g.Roots[0])
	if root.Attr["pypi.source"] != "Pipfile" {
		t.Errorf("root source = %q, want Pipfile", root.Attr["pypi.source"])
	}
	// A manifest resolves no tree -> flat-resolution disclosure (D-24).
	if root.Attr[graph.AttrFlatResolution] != "pypi" {
		t.Errorf("Pipfile must carry flat-resolution, got %q", root.Attr[graph.AttrFlatResolution])
	}
	// All four deps (both tables) captured as declared + unresolved.
	un := root.Attr[graph.AttrUnresolved]
	for _, name := range []string{"requests", "flask", "django", "pytest"} {
		if !contains(un, name) {
			t.Errorf("declared dep %q missing from unresolved=%q", name, un)
		}
	}
	// The inline-table version for flask must be extracted (not "*").
	dd := root.Attr[graph.AttrDeclaredDeps]
	if !contains(dd, "flask") || !contains(dd, ">=2.0") {
		t.Errorf("flask constraint not extracted from inline table; declared=%q", dd)
	}
}

func TestParsePipfileNoDeps(t *testing.T) {
	src := "[[source]]\nurl = \"https://pypi.org/simple\"\n\n[requires]\npython_version = \"3.11\"\n"
	if _, err := parsePipfile("proj/Pipfile", []byte(src)); err == nil {
		t.Error("a Pipfile with no [packages]/[dev-packages] deps should error")
	}
}

func TestPipfileConstraint(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"*"`, "*"},
		{`">=2.0"`, ">=2.0"},
		{`{version = ">=2.0", extras = ["async"]}`, ">=2.0"},
		{`{editable = true, path = "."}`, "*"}, // table with no version -> unpinned
	}
	for _, c := range cases {
		if got := pipfileConstraint(c.in); got != c.want {
			t.Errorf("pipfileConstraint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
