package pypi

import (
	"context"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/pep440"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
)

// WalkSource is PyPI's side of the Nth-layer walk: what a coordinate declares,
// what versions exist, and what PEP 440 says about a constraint.
//
// It composes the clients that already exist rather than adding a third way to
// talk to PyPI. Deps is the same requires_dist client cmd/depsnort already
// builds for depth reconstruction; Versions is the same release-history client
// VC-004/VC-005 use for publish times. The walk needed no new network surface —
// only the metadata already being fetched, kept instead of discarded.
//
// Both are optional. Without Deps the walk cannot read declarations at all;
// without Index it can read them but never presume, so it discovers names
// one layer down and stops. Neither degradation is silent: expand records a
// frontier either way.
type WalkSource struct {
	Deps  *registry.PyPIDepsClient
	Index *registry.Client
}

func (*WalkSource) Ecosystem() string { return "pypi" }

// Identify normalizes per PEP 503 before a name becomes a node identity.
//
// This is the leak D-15 found and closed once: without folding,
// Flask_SQLAlchemy and flask-sqlalchemy are two nodes, and every dedupe
// downstream silently fails. It lives here rather than in the shared walk
// because the folding rule is PyPI's, not the engine's.
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	canonical = purl.NormalizePyPI(name)
	if canonical == "" {
		return "", ""
	}
	return purl.NewPyPI(canonical, version).String(), canonical
}

// Declared returns each coordinate's requires_dist, reduced to names and
// constraints. A coordinate ABSENT from the result was not read — the client
// preserves that distinction, and expand counts it as a frontier rather than a
// package that declares nothing.
func (w *WalkSource) Declared(ctx context.Context, coords []datasource.Coord) (map[string][]expand.Declaration, error) {
	if w.Deps == nil {
		return nil, nil
	}
	raw, err := w.Deps.Requirements(ctx, coords)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]expand.Declaration, len(raw))
	for key, reqs := range raw {
		decls := make([]expand.Declaration, 0, len(reqs))
		for _, r := range reqs {
			if r.Name == "" {
				continue
			}
			decls = append(decls, expand.Declaration{
				Name:       r.Name,
				Constraint: r.Specifier,
				// A platform-excluded dependency declares what MIGHT be
				// installed. Marked optional so the default walk does not
				// inflate the tree with packages no ordinary install pulls.
				// (Extras-gated entries are already dropped by the client, the
				// same way name-only reconstruction drops them.)
				Optional: pep508.ExcludesLinux(r.Marker),
			})
		}
		out[key] = decls
	}
	return out, nil
}

// Versions lists published versions, reusing the release-history client.
func (w *WalkSource) Versions(ctx context.Context, _, name string) ([]string, error) {
	if w.Index == nil {
		return nil, nil
	}
	hist, err := w.Index.Histories(ctx, []string{name})
	if err != nil {
		return nil, err
	}
	h := hist[name]
	if h == nil {
		return nil, nil
	}
	out := make([]string, 0, len(h.Releases))
	for _, r := range h.Releases {
		out = append(out, r.Version)
	}
	return out, nil
}

// Satisfies evaluates a PEP 440 specifier. The second return is whether the
// constraint could be read at all: an unreadable grammar is neither satisfied
// nor violated, and reporting it as violated would silently exclude candidates
// the operator never excluded.
func (*WalkSource) Satisfies(constraint, version string) (ok, evaluable bool) {
	return pep440.Satisfies(constraint, version)
}

// CompareVersions orders two PyPI versions. Not semver: 1.0.post1 outranks 1.0,
// 1.0.dev1 sorts below 1.0a1, and an epoch outranks any release number.
func (*WalkSource) CompareVersions(a, b string) int {
	pa, pb := pep440.Parse(a), pep440.Parse(b)
	switch {
	case !pa.Valid && !pb.Valid:
		return 0
	case !pa.Valid:
		return -1 // an unparseable tag never wins a "highest satisfying" race
	case !pb.Valid:
		return 1
	}
	return pep440.Compare(pa, pb)
}

// Compile-time proof that PyPI satisfies every seam the walk offers: it can
// declare, it can index, and it can judge a constraint.
var (
	_ expand.Declarer     = (*WalkSource)(nil)
	_ expand.VersionIndex = (*WalkSource)(nil)
	_ expand.Presumer     = (*WalkSource)(nil)
)
