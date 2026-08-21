package pypi

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// A minimal uv.lock exercising the shapes the reader must handle: an editable
// root with runtime + dev-group deps, a registry leaf, a registry package with
// its own transitive deps, and an empty-dependencies line.
const sampleUvLock = `version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "annotated-types"
version = "0.8.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://example/annotated_types-0.8.0-py3-none-any.whl", hash = "sha256:deadbeef" },
]

[[package]]
name = "pydantic"
version = "2.13.4"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "annotated-types" },
    { name = "typing-extensions" },
]

[[package]]
name = "typing-extensions"
version = "4.16.0"
source = { registry = "https://pypi.org/simple" }
dependencies = []

[[package]]
name = "demo"
version = "3.0.1"
source = { editable = "." }
dependencies = [
    { name = "pydantic" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
`

func TestParseUvLock(t *testing.T) {
	g, err := parseUvLock("demo/uv.lock", []byte(sampleUvLock))
	if err != nil {
		t.Fatalf("parseUvLock: %v", err)
	}

	// Root is the editable project, with its real locked version.
	if len(g.Roots) != 1 || g.Roots[0] != "pkg:pypi/demo@3.0.1" {
		t.Fatalf("root = %v, want [pkg:pypi/demo@3.0.1]", g.Roots)
	}

	// Every locked package became an observed node.
	for _, want := range []string{
		"pkg:pypi/annotated-types@0.8.0",
		"pkg:pypi/pydantic@2.13.4",
		"pkg:pypi/typing-extensions@4.16.0",
		"pkg:pypi/pytest@8.0.0",
	} {
		if g.Get(want) == nil {
			t.Errorf("missing node %s", want)
		}
	}

	// Transitive edges are real, not flat: pydantic -> annotated-types must exist.
	if !hasEdge(g, "pkg:pypi/pydantic@2.13.4", "pkg:pypi/annotated-types@0.8.0", graph.EdgeDependsOn) {
		t.Error("missing transitive edge pydantic -> annotated-types")
	}
	// Root -> runtime dep.
	if !hasEdge(g, "pkg:pypi/demo@3.0.1", "pkg:pypi/pydantic@2.13.4", graph.EdgeDependsOn) {
		t.Error("missing root -> pydantic runtime edge")
	}
	// Root -> dev dep (OPU-13: dev deps are install surface).
	if !hasEdge(g, "pkg:pypi/demo@3.0.1", "pkg:pypi/pytest@8.0.0", graph.EdgeDependsOn) {
		t.Error("missing root -> pytest dev edge")
	}

	// Section tagging distinguishes runtime from dev.
	if s := section(g, "pkg:pypi/pydantic@2.13.4"); s != "runtime" {
		t.Errorf("pydantic section = %q, want runtime", s)
	}
	if s := section(g, "pkg:pypi/pytest@8.0.0"); !strings.HasPrefix(s, "dev:") {
		t.Errorf("pytest section = %q, want dev:*", s)
	}

	// Provenance flows through from source.
	if cls, _ := g.Get("pkg:pypi/pydantic@2.13.4").SourceOf(); cls != graph.SourceRegistry {
		t.Errorf("pydantic source class = %q, want registry", cls)
	}

	// Real depths: annotated-types sits below the root, not at depth 1.
	if d := g.Get("pkg:pypi/annotated-types@0.8.0").Depth; d < 2 {
		t.Errorf("annotated-types depth = %d, want >= 2 (real tree, not flat)", d)
	}

	// The flat-resolution penalty must NOT be recorded — uv.lock has edges.
	if g.Get("pkg:pypi/demo@3.0.1").Attr[graph.AttrFlatResolution] != "" {
		t.Error("uv.lock must not be marked flat-resolution")
	}
}

func section(g *graph.Graph, id string) string {
	if n := g.Get(id); n != nil && n.Attr != nil {
		return n.Attr["pypi.section"]
	}
	return ""
}
