package cargo

import (
	"context"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/semver"
)

// WalkSource is Cargo's side of the Nth-layer walk (D-44): what a crate
// declares, what versions crates.io published, and what a Cargo version
// requirement admits.
//
// Like the npm and PyPI sources it adds no network surface beyond the crates.io
// metadata the tool already reads: Deps is the per-version dependencies
// endpoint, Index is the release-history client VC-004/VC-005 use.
type WalkSource struct {
	Deps  *registry.CargoDepsClient
	Index *registry.Client
}

func (*WalkSource) Ecosystem() string { return "cargo" }

// Identify builds Cargo's canonical node identity. Crate names are used
// verbatim — crates.io treats `-` and `_` as distinct and forbids confusable
// new names, so unlike PyPI there is nothing to fold, and folding would MERGE
// two crates crates.io keeps apart.
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	if name == "" {
		return "", ""
	}
	return purl.NewCargo(name, version).String(), name
}

// Declared returns each crate's dependencies with their version requirements.
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
				Constraint: r.Req,
				Optional:   r.Optional,
			})
		}
		out[key] = decls
	}
	return out, nil
}

// Versions lists a crate's published versions from the release-history client.
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

// Satisfies evaluates a Cargo version requirement. Cargo's grammar is not npm's:
// a bare "1.2.3" is a caret requirement, and AND is a comma. The second return
// reports whether the requirement could be read; an unreadable one declines so
// the walk marks the node contested rather than excluding a candidate.
func (*WalkSource) Satisfies(constraint, version string) (ok, evaluable bool) {
	return semver.SatisfiesCargo(constraint, version)
}

// CompareVersions orders two crate versions, prerelease-aware.
func (*WalkSource) CompareVersions(a, b string) int {
	return semver.Parse(a).Compare(semver.Parse(b))
}

var (
	_ expand.Declarer     = (*WalkSource)(nil)
	_ expand.VersionIndex = (*WalkSource)(nil)
	_ expand.Presumer     = (*WalkSource)(nil)
)
