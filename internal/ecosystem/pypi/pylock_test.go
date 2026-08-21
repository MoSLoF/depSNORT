package pypi

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// The canonical PEP 751 example (abridged): attrs, cattrs (-> attrs), numpy.
// Single-quoted strings, an inline multi-line `dependencies` array, [[packages.wheels]]
// and [[packages.attestation-identities]] sub-tables, and a trailing [tool] table.
const samplePylockCanonical = `lock-version = '1.0'
environments = ["sys_platform == 'win32'", "sys_platform == 'linux'"]
requires-python = '== 3.12.*'
created-by = 'mousebender'

[[packages]]
name = 'attrs'
version = '25.1.0'
requires-python = '>= 3.8'
index = 'https://pypi.org/simple'

    [[packages.wheels]]
    name = 'attrs-25.1.0-py3-none-any.whl'
    url = 'https://files.pythonhosted.org/packages/fc/attrs-25.1.0-py3-none-any.whl'
    hashes = {sha256 = 'aaa'}

    [[packages.attestation-identities]]
    kind = 'GitHub'

[[packages]]
name = 'cattrs'
version = '24.1.2'
index = 'https://pypi.org/simple'
dependencies = [
    {name = 'attrs'},
]

    [[packages.wheels]]
    name = 'cattrs-24.1.2-py3-none-any.whl'
    url = 'https://files.pythonhosted.org/packages/c8/cattrs-24.1.2-py3-none-any.whl'
    hashes = {sha256 = 'bbb'}

[[packages]]
name = 'numpy'
version = '2.2.3'
index = 'https://pypi.org/simple'

    [[packages.wheels]]
    name = 'numpy-2.2.3-cp312-cp312-win_amd64.whl'
    url = 'https://files.pythonhosted.org/packages/42/numpy-2.2.3-cp312-cp312-win_amd64.whl'
    hashes = {sha256 = 'ccc'}

[tool.mousebender]
command = ['.', 'lock', 'cattrs', 'numpy']
`

func TestParsePylockCanonical(t *testing.T) {
	g, err := parsePylock("proj/pylock.toml", []byte(samplePylockCanonical))
	if err != nil {
		t.Fatalf("parsePylock: %v", err)
	}

	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want exactly one synthesized root", g.Roots)
	}
	rootID := g.Roots[0]
	if a := g.Get(rootID).Attr["pypi.direct_attribution"]; a != "in-degree-zero" {
		t.Errorf("root direct_attribution = %q, want in-degree-zero", a)
	}

	for _, want := range []string{
		"pkg:pypi/attrs@25.1.0", "pkg:pypi/cattrs@24.1.2", "pkg:pypi/numpy@2.2.3",
	} {
		if g.Get(want) == nil {
			t.Errorf("missing node %s", want)
		}
	}

	// Edge from the informational `dependencies` array: cattrs -> attrs.
	if !hasEdge(g, "pkg:pypi/cattrs@24.1.2", "pkg:pypi/attrs@25.1.0", graph.EdgeDependsOn) {
		t.Error("missing edge cattrs -> attrs")
	}
	// attrs is depended upon, so it is reached transitively, not attached to root.
	if hasEdge(g, rootID, "pkg:pypi/attrs@25.1.0", graph.EdgeDependsOn) {
		t.Error("attrs should be transitive, not a direct root edge")
	}
	if g.Get("pkg:pypi/attrs@25.1.0").Depth < 2 {
		t.Errorf("attrs depth = %d, want >= 2", g.Get("pkg:pypi/attrs@25.1.0").Depth)
	}
	// cattrs and numpy are in-degree zero -> direct root edges.
	for _, id := range []string{"pkg:pypi/cattrs@24.1.2", "pkg:pypi/numpy@2.2.3"} {
		if !hasEdge(g, rootID, id, graph.EdgeDependsOn) {
			t.Errorf("%s (in-degree zero) should be a direct root edge", id)
		}
	}

	// index -> registry source.
	if c := g.Get("pkg:pypi/cattrs@24.1.2").Attr[graph.AttrSourceClass]; c != graph.SourceRegistry {
		t.Errorf("cattrs source class = %q, want registry", c)
	}

	// The graph is edged, so NO flat-resolution penalty.
	if v := g.Get(rootID).Attr[graph.AttrFlatResolution]; v != "" {
		t.Errorf("edged pylock must not carry flat-resolution, got %q", v)
	}
}

// An edgeless pylock (no `dependencies` anywhere — the common tool output) must
// fall back to flat resolution and DISCLOSE it, with every package direct.
const samplePylockEdgeless = `lock-version = '1.0'
created-by = 'pipenv'

[[packages]]
name = 'requests'
version = '2.28.1'
index = 'https://pypi.org/simple/'

    [[packages.wheels]]
    name = 'requests-2.28.1-py3-none-any.whl'
    url = 'https://files.pythonhosted.org/packages/requests-2.28.1-py3-none-any.whl'

[[packages]]
name = 'certifi'
version = '2022.12.7'
sdist = { url = 'https://files.pythonhosted.org/packages/certifi-2022.12.7.tar.gz', hashes = { sha256 = 'ddd' } }
`

func TestParsePylockEdgelessIsFlat(t *testing.T) {
	g, err := parsePylock("proj/pylock.toml", []byte(samplePylockEdgeless))
	if err != nil {
		t.Fatalf("parsePylock: %v", err)
	}
	rootID := g.Roots[0]
	if v := g.Get(rootID).Attr[graph.AttrFlatResolution]; v != "pypi" {
		t.Errorf("edgeless pylock must disclose flat-resolution, got %q", v)
	}
	for _, id := range []string{"pkg:pypi/requests@2.28.1", "pkg:pypi/certifi@2022.12.7"} {
		if !hasEdge(g, rootID, id, graph.EdgeDependsOn) {
			t.Errorf("%s should be a direct root edge in a flat lock", id)
		}
	}
	// Inline sdist url is extracted cleanly (not swept up with trailing hashes).
	if r := g.Get("pkg:pypi/certifi@2022.12.7").Attr[graph.AttrSourceRef]; r != "https://files.pythonhosted.org/packages/certifi-2022.12.7.tar.gz" {
		t.Errorf("certifi source ref = %q, want the sdist url only", r)
	}
}

// Every PEP 751 source shape maps to the right provenance class.
const samplePylockSources = `lock-version = '1.0'
created-by = 'test'

[[packages]]
name = 'reg-pkg'
version = '1.0.0'
index = 'https://pypi.org/simple'

[[packages]]
name = 'vcs-pkg'
version = '2.0.0'

    [packages.vcs]
    type = 'git'
    url = 'https://github.com/example/vcs-pkg'
    commit-id = 'deadbeef'

[[packages]]
name = 'dir-pkg'
version = '3.0.0'

    [packages.directory]
    path = '../dir-pkg'
    editable = true

[[packages]]
name = 'archive-pkg'
version = '4.0.0'

    [packages.archive]
    url = 'https://example.com/archive-pkg-4.0.0.zip'
`

func TestParsePylockSourceClassification(t *testing.T) {
	g, err := parsePylock("proj/pylock.toml", []byte(samplePylockSources))
	if err != nil {
		t.Fatalf("parsePylock: %v", err)
	}
	cases := []struct {
		id, class, ref string
	}{
		{"pkg:pypi/reg-pkg@1.0.0", graph.SourceRegistry, "https://pypi.org/simple"},
		{"pkg:pypi/vcs-pkg@2.0.0", graph.SourceGit, "https://github.com/example/vcs-pkg"},
		{"pkg:pypi/dir-pkg@3.0.0", graph.SourcePath, "../dir-pkg"},
		{"pkg:pypi/archive-pkg@4.0.0", graph.SourceURL, "https://example.com/archive-pkg-4.0.0.zip"},
	}
	for _, c := range cases {
		n := g.Get(c.id)
		if n == nil {
			t.Errorf("missing node %s", c.id)
			continue
		}
		if got := n.Attr[graph.AttrSourceClass]; got != c.class {
			t.Errorf("%s source class = %q, want %q", c.id, got, c.class)
		}
		if got := n.Attr[graph.AttrSourceRef]; got != c.ref {
			t.Errorf("%s source ref = %q, want %q", c.id, got, c.ref)
		}
	}
}

func TestParsePylockEmpty(t *testing.T) {
	_, err := parsePylock("proj/pylock.toml", []byte("lock-version = '1.0'\ncreated-by = 'x'\n"))
	if err == nil {
		t.Error("a pylock with no [[packages]] should error")
	}
}

func TestParsePylockFormatMismatchDisclosed(t *testing.T) {
	src := "lock-version = '2.0'\ncreated-by = 'x'\n\n[[packages]]\nname = 'a'\nversion = '1.0.0'\n"
	g, err := parsePylock("proj/pylock.toml", []byte(src))
	if err != nil {
		t.Fatalf("parsePylock: %v", err)
	}
	if v := g.Get(g.Roots[0]).Attr["pypi.pylock_format"]; v != "2.0" {
		t.Errorf("unsupported lock-version should be disclosed, got %q", v)
	}
}

func TestPylockDetection(t *testing.T) {
	for _, name := range []string{"pylock.toml", "pylock.dev.toml", "pylock.spam.toml"} {
		if !isPylockFile(name) {
			t.Errorf("isPylockFile(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"pylock.toml.bak", "mypylock.toml", "pylock.a.b.toml", "poetry.lock", "pylock.toml.txt"} {
		if isPylockFile(name) {
			t.Errorf("isPylockFile(%q) = true, want false", name)
		}
	}
}
