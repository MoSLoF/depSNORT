package nuget

import (
	"context"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/nugetver"
	"ihbv.io/depsnort/internal/purl"
)

// WalkSource is NuGet's side of the Nth-layer walk (D-44): what a package
// declares, what versions the feed published, and what a NuGet version range
// admits — plus the one thing that makes NuGet different from every other
// ecosystem here: it resolves to the LOWEST satisfying version, not the highest.
//
// It adds no network surface beyond the registration index the tool already
// reads: Deps pulls dependency groups from it, Index reads its versions.
type WalkSource struct {
	Deps  *registry.NuGetDepsClient
	Index *registry.Client
}

func (*WalkSource) Ecosystem() string { return "nuget" }

// Identify lowercases the package id before it becomes a node identity. NuGet
// ids are case-insensitive, so "Newtonsoft.Json" and "newtonsoft.json" are one
// package; folding here keeps them one node, the same leak class D-15 closed for
// PyPI. This matches purl.NewNuGet, which also lowercases.
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	if name == "" {
		return "", ""
	}
	p := purl.NewNuGet(name, version)
	return p.String(), p.Name // p.Name is already lowercased
}

// Declared returns each package's dependencies with their NuGet version ranges.
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
			decls = append(decls, expand.Declaration{Name: r.Name, Constraint: r.Range})
		}
		out[key] = decls
	}
	return out, nil
}

// Versions lists a package's published versions from the registration index.
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

// Satisfies evaluates a NuGet version range — interval notation, with a bare
// version meaning a minimum. The second return is whether the range could be
// read; an unreadable one declines so the walk marks the node contested.
func (*WalkSource) Satisfies(constraint, version string) (ok, evaluable bool) {
	if constraint == "" {
		return true, true // NuGet: an unversioned dependency accepts any version
	}
	return nugetver.Satisfies(constraint, version)
}

// CompareVersions orders two NuGet versions (four-part, prerelease-aware).
func (*WalkSource) CompareVersions(a, b string) int {
	pa, pb := nugetver.Parse(a), nugetver.Parse(b)
	switch {
	case !pa.Valid && !pb.Valid:
		return 0
	case !pa.Valid:
		return -1
	case !pb.Valid:
		return 1
	}
	return nugetver.Compare(pa, pb)
}

// PrefersLowest reports true: NuGet's resolver installs the lowest version that
// satisfies a dependency's range, not the newest. Presuming the highest would
// model a restore no NuGet client performs.
func (*WalkSource) PrefersLowest() bool { return true }

var (
	_ expand.Declarer       = (*WalkSource)(nil)
	_ expand.VersionIndex   = (*WalkSource)(nil)
	_ expand.Presumer       = (*WalkSource)(nil)
	_ expand.LowestResolver = (*WalkSource)(nil)
)
