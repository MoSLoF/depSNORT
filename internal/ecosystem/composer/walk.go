package composer

import (
	"context"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/registry"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/semver"
)

// WalkSource is Composer's side of the Nth-layer walk (D-44). It adds no network
// surface beyond the Packagist metadata the tool already reads: Deps pulls the
// per-version `require` map from the p2 endpoint, Index reads the version list.
type WalkSource struct {
	Deps  *registry.ComposerDepsClient
	Index *registry.Client
}

func (*WalkSource) Ecosystem() string { return "composer" }

// Identify keeps the vendor/package form and lowercases it — Packagist package
// names are case-insensitive, so "Monolog/Monolog" and "monolog/monolog" are
// one package, one node (the D-15 leak class). purl.NewComposer splits the
// vendor namespace out of the same string.
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	if name == "" {
		return "", ""
	}
	canon := lower(name)
	return purl.NewComposer(canon, version).String(), canon
}

// Declared returns each package's non-platform dependencies with their
// constraints.
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
			decls = append(decls, expand.Declaration{Name: r.Name, Constraint: r.Constraint})
		}
		out[key] = decls
	}
	return out, nil
}

// Versions lists a package's published versions.
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

// Satisfies evaluates a Composer constraint: caret, the pessimistic tilde
// (distinct from npm's), comparators, "||" OR, and wildcards. An unreadable
// constraint — including a stability suffix this subset does not model —
// declines.
func (*WalkSource) Satisfies(constraint, version string) (ok, evaluable bool) {
	if constraint == "" {
		return true, true
	}
	return semver.SatisfiesComposer(constraint, version)
}

// CompareVersions orders two Composer versions, prerelease-aware. A leading "v"
// is tolerated by semver.Parse.
func (*WalkSource) CompareVersions(a, b string) int {
	return semver.Parse(a).Compare(semver.Parse(b))
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

var (
	_ expand.Declarer     = (*WalkSource)(nil)
	_ expand.VersionIndex = (*WalkSource)(nil)
	_ expand.Presumer     = (*WalkSource)(nil)
)
