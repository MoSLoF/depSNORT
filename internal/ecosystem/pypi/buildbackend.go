package pypi

import (
	"context"
	"sort"
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
		// A standard, unpinned build backend (setuptools / hatchling /
		// poetry-core / pdm-backend / flit / maturin / ...) is the universal,
		// benign case: nearly every package declares one and few pin it to a
		// concrete version. Counting each as an unresolved coverage gap makes
		// almost every scan read "incomplete" for no actionable reason —
		// especially now that lockfile readers expose the full transitive
		// closure (OPU-29). Record a KNOWN backend as a disclosed-but-non-gating
		// fact instead, and reserve the coverage gate for UNKNOWN backends,
		// whose unresolvability is a genuine signal (Decision: OPU-29).
		if installsurface.IsKnownBuildBackend(backend) {
			// Record the ACTUAL backend module reference (e.g. hatchling.build),
			// not just the requires-entry package name, so a watch/drift rule sees
			// the real value that executes at build time rather than a sanitized
			// one (OPU-30).
			addKnownBackend(consumer, backend)
			return
		}
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

// addKnownBackend records a standard, unpinned PEP 517 build backend as a
// disclosed-but-non-gating fact on the consumer (attr "pypi.build_backend"),
// deliberately kept OUT of graph.AttrUnresolved so it does not degrade coverage.
// This mirrors the pypi.marker_excluded convention: the situation is surfaced,
// not silently dropped, but it does not read as a real gap. The names are kept
// sorted and de-duplicated so the attr is deterministic (D-09/D-13).
func addKnownBackend(n *graph.Node, backendRef string) {
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	set := map[string]bool{}
	if existing := n.Attr["pypi.build_backend"]; existing != "" {
		for _, s := range strings.Split(existing, ",") {
			set[s] = true
		}
	}
	set[backendRef] = true
	names := make([]string, 0, len(set))
	for s := range set {
		names = append(names, s)
	}
	sort.Strings(names)
	n.Attr["pypi.build_backend"] = strings.Join(names, ",")
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
