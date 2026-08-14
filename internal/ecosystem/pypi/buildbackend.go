package pypi

import (
	"context"
	"strconv"
	"strings"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
)

// resolveBuildBackend recursively analyzes a package's own PEP 517 build
// backend, when pyprojectToml pins it to a specific version via
// build-system.requires. A build backend is code that runs at build time for
// every consumer of the package, so it gets exactly the same install-surface
// treatment as any other dependency (Decision D-03: extraction, not
// judgment) — modeled as an ordinary KindPackage node reachable from consumer
// via graph.EdgeBuildBackend, so VC-002's collectHooks picks up its hooks
// with zero changes.
//
// requires is intentionally NOT range-satisfied (Decision D-01): an
// unpinned build-system.requires entry (the common case — "setuptools>=64")
// cannot be resolved to one concrete version without reimplementing a
// resolver, so it is recorded as an ordinary unresolved dependency instead.
func (a *Adapter) resolveBuildBackend(ctx context.Context, g *graph.Graph, consumer *graph.Node, pyprojectToml string, processed map[string]bool, gaps *instsurf.Gaps) {
	backend := installsurface.ExtractBuildBackend(pyprojectToml)
	if backend == "" {
		return
	}
	requires := installsurface.ExtractBuildRequires(pyprojectToml)

	// ok==false or ambiguous==true means analyzeBuildBackend's hook (if any
	// hook fired at all) already recorded WHY via its own Evidence
	// ("missing-requires-entry" / "ambiguous-build-backend-requires") — there
	// is nothing further this function can responsibly resolve.
	matched, ok, ambiguous := installsurface.MatchBuildBackendRequires(backend, requires)
	if !ok || ambiguous {
		return
	}

	name, version, pinned, _ := pep508.Split(matched)
	if !pinned {
		addUnresolved(consumer, name)
		return
	}

	if a.Sdist == nil {
		return
	}

	backendID := purl.NewPyPI(name, version).String()
	// AddNode is first-write-wins: a backend that is ALSO an ordinary declared
	// dependency keeps its existing Depth/Direct/other Attr, and only gains
	// the build-backend role attr and edge below rather than losing its
	// identity to a duplicate node.
	backendNode := g.AddNode(&graph.Node{
		ID: backendID, Ecosystem: "pypi", Name: purl.NormalizePyPI(name), Version: version,
		Depth: consumer.Depth + 1,
	})
	if backendNode.Attr == nil {
		backendNode.Attr = map[string]string{}
	}
	backendNode.Attr["pypi.role"] = "build-backend"
	g.AddEdge(consumer.ID, backendID, graph.EdgeBuildBackend)

	// A build backend used by several consumers is fetched and analyzed once;
	// every consumer still gets its own edge above.
	if processed[backendID] {
		return
	}
	processed[backendID] = true

	files, err := a.Sdist.Fetch(ctx, name, version)
	if err != nil {
		gaps.AddReason(backendID, name+"@"+version, instsurf.GapUnreadable, err)
		return
	}
	if files.SetupPy == "" && files.PyprojectToml == "" && len(files.PthFiles) == 0 {
		return
	}
	surface := installsurface.AnalyzePython(files.SetupPy, files.PyprojectToml, files.PthFiles)
	if len(surface.Hooks) > 0 {
		addPySurfaceToGraph(g, backendNode, surface)
	}
}

// addUnresolved reuses graph.AttrUnresolved/AttrUnresolvedCount — the same
// bookkeeping an unpinned requirements.txt line already gets — so a
// build-backend requirement this tool declines to pin to a fetchable version
// registers as the same coverage gap.
func addUnresolved(n *graph.Node, name string) {
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	var names []string
	if existing := n.Attr[graph.AttrUnresolved]; existing != "" {
		names = strings.Split(existing, ",")
	}
	names = append(names, name)
	n.Attr[graph.AttrUnresolved] = strings.Join(names, ",")
	n.Attr[graph.AttrUnresolvedCount] = strconv.Itoa(len(names))
}
