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

// A rootless uv.lock: an application-style lock (or `uv pip compile` export)
// with NO editable/virtual self-entry — just resolved registry packages with
// inter-package edges. This must synthesize a root and attach the in-degree-zero
// packages (the poetry/pdm/pylock shape), not error out. Regression for the
// open-webui live-fire, whose uv.lock is exactly this.
const sampleUvLockRootless = `version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "aiohttp"
version = "3.13.5"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "aiohappyeyeballs" },
    { name = "multidict" },
]

[[package]]
name = "aiohappyeyeballs"
version = "2.6.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "multidict"
version = "6.1.0"
source = { registry = "https://pypi.org/simple" }
`

func TestParseUvLockRootless(t *testing.T) {
	g, err := parseUvLock("app/uv.lock", []byte(sampleUvLockRootless))
	if err != nil {
		t.Fatalf("rootless uv.lock must resolve, got error: %v", err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want one synthesized root", g.Roots)
	}
	rootID := g.Roots[0]
	if a := g.Get(rootID).Attr["pypi.direct_attribution"]; a != "in-degree-zero" {
		t.Errorf("synthesized root direct_attribution = %q, want in-degree-zero", a)
	}
	// The synthesized root is NOT one of the package nodes.
	for _, id := range []string{
		"pkg:pypi/aiohttp@3.13.5", "pkg:pypi/aiohappyeyeballs@2.6.1", "pkg:pypi/multidict@6.1.0",
	} {
		if g.Get(id) == nil {
			t.Errorf("missing node %s", id)
		}
	}
	// aiohttp is in-degree zero -> a direct root edge.
	if !hasEdge(g, rootID, "pkg:pypi/aiohttp@3.13.5", graph.EdgeDependsOn) {
		t.Error("aiohttp (in-degree zero) should be a direct root edge")
	}
	if !g.Get("pkg:pypi/aiohttp@3.13.5").Direct {
		t.Error("aiohttp should be marked Direct")
	}
	// Its deps are real transitive edges, not flat.
	if !hasEdge(g, "pkg:pypi/aiohttp@3.13.5", "pkg:pypi/aiohappyeyeballs@2.6.1", graph.EdgeDependsOn) ||
		!hasEdge(g, "pkg:pypi/aiohttp@3.13.5", "pkg:pypi/multidict@6.1.0", graph.EdgeDependsOn) {
		t.Error("missing aiohttp -> {aiohappyeyeballs, multidict} edges")
	}
	if hasEdge(g, rootID, "pkg:pypi/aiohappyeyeballs@2.6.1", graph.EdgeDependsOn) {
		t.Error("aiohappyeyeballs is transitive; must not be a direct root edge")
	}
	if d := g.Get("pkg:pypi/aiohappyeyeballs@2.6.1").Depth; d < 2 {
		t.Errorf("aiohappyeyeballs depth = %d, want >= 2 (real tree, not flat)", d)
	}
	// Real edges -> no flat-resolution penalty.
	if v := g.Get(rootID).Attr[graph.AttrFlatResolution]; v != "" {
		t.Errorf("rootless uv.lock has real edges; must not carry flat-resolution, got %q", v)
	}
}
