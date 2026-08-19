package rubygems

import (
	"context"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/semver"
)

// WalkSource is RubyGems' side of the Nth-layer walk (D-44). It adds no network
// surface beyond the RubyGems metadata the tool already reads: Deps pulls
// per-version runtime dependencies from the v2 API, Index reads the version
// list.
type WalkSource struct {
	Deps  *registry.GemDepsClient
	Index *registry.Client
}

func (*WalkSource) Ecosystem() string { return "gem" }

// Identify uses the gem name verbatim. Gem names are case-sensitive and carry
// no scope, so there is nothing to fold.
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	if name == "" {
		return "", ""
	}
	return purl.NewGem(name, version).String(), name
}

// Declared returns each gem's runtime dependencies with their requirements.
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
			decls = append(decls, expand.Declaration{Name: r.Name, Constraint: r.Req})
		}
		out[key] = decls
	}
	return out, nil
}

// Versions lists a gem's published versions.
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

// Satisfies evaluates a RubyGems requirement: the "~>" pessimistic operator,
// comma-AND, and a bare version as exact. An unreadable requirement declines.
func (*WalkSource) Satisfies(constraint, version string) (ok, evaluable bool) {
	if constraint == "" {
		return true, true
	}
	return semver.SatisfiesRuby(constraint, version)
}

// CompareVersions orders two gem versions, prerelease-aware.
func (*WalkSource) CompareVersions(a, b string) int {
	return semver.Parse(a).Compare(semver.Parse(b))
}

var (
	_ expand.Declarer     = (*WalkSource)(nil)
	_ expand.VersionIndex = (*WalkSource)(nil)
	_ expand.Presumer     = (*WalkSource)(nil)
)
