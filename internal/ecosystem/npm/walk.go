package npm

import (
	"context"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/npmreg"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/semver"
)

// WalkSource is npm's side of the Nth-layer walk (D-44): what a coordinate
// declares, what versions exist, and what a semver range admits.
//
// Like the PyPI source, it adds no network surface. The npm packument already
// carries per-version `dependencies` and the full `time`/version map, and the
// registry client is the same one VC-004/VC-005 fetch through; the walk reads
// declarations and the version list from that one document.
type WalkSource struct {
	Reg *npmreg.Client
}

func (*WalkSource) Ecosystem() string { return "npm" }

// Identify builds npm's canonical node identity, splitting a scoped name into
// namespace/name so "@acme/util" and a bare "util" never collide. npm names are
// case-sensitive, so unlike PyPI there is no folding to apply — but the split
// still has to happen HERE, in the ecosystem seam, because the shared walk does
// not know npm has scopes.
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	if name == "" {
		return "", ""
	}
	return purl.NewNpm(name, version).String(), name
}

// Declared returns each coordinate's dependencies with their semver ranges. A
// coordinate absent from the result was not read — the client preserves that,
// and expand counts it as a frontier rather than a package that declares
// nothing.
func (w *WalkSource) Declared(ctx context.Context, coords []datasource.Coord) (map[string][]expand.Declaration, error) {
	if w.Reg == nil {
		return nil, nil
	}
	raw, err := w.Reg.Requirements(ctx, coords)
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
				Constraint: r.Range,
				Optional:   r.Optional,
			})
		}
		out[key] = decls
	}
	return out, nil
}

// Versions lists a package's published versions, from the same packument.
func (w *WalkSource) Versions(ctx context.Context, _, name string) ([]string, error) {
	if w.Reg == nil {
		return nil, nil
	}
	hist, err := w.Reg.Histories(ctx, []string{name})
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

// Satisfies evaluates an npm semver range. The second return is whether the
// range could be read at all: an unreadable one is neither satisfied nor
// violated, so the walk marks the node contested rather than excluding a
// candidate the range never excluded.
func (*WalkSource) Satisfies(constraint, version string) (ok, evaluable bool) {
	return semver.Satisfies(constraint, version)
}

// CompareVersions orders two npm versions, prerelease-aware.
func (*WalkSource) CompareVersions(a, b string) int {
	return semver.Parse(a).Compare(semver.Parse(b))
}

var (
	_ expand.Declarer     = (*WalkSource)(nil)
	_ expand.VersionIndex = (*WalkSource)(nil)
	_ expand.Presumer     = (*WalkSource)(nil)
)
