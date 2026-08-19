package gomod

import (
	"context"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/datasource/goproxy"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/semver"
)

// WalkSource is Go's side of the Nth-layer walk (D-44). go.mod records a flat,
// pinned require set but no inter-module edges, so expansion rebuilds the real
// tree by reading each module's own go.mod from the proxy.
//
// # Why Go is a lowest-resolver
//
// A go.mod `require M vX` is a MINIMUM: the build needs at least vX of M. Go's
// minimal-version-selection then picks, for each module, the MAXIMUM among all
// the minimums any module requires — which is the LOWEST version that satisfies
// every ">= vX" at once. So Go expresses each require as ">=version" and selects
// the lowest satisfying candidate, exactly the NuGet-shaped resolution the walk
// already supports through LowestResolver. Presuming the newest available
// version instead would model an upgrade Go never performs.
type WalkSource struct {
	Proxy *goproxy.Client
}

func (*WalkSource) Ecosystem() string { return "gomod" }

// Identify uses the full module path as the node's identity — Go's identity is
// the module path, including any /vN major suffix. Case is preserved: module
// paths are case-sensitive (the proxy's !-escaping is a transport detail,
// applied only in goproxy).
func (*WalkSource) Identify(name, version string) (id, canonical string) {
	if name == "" {
		return "", ""
	}
	return purl.NewGo(name, version).String(), name
}

// Declared returns each module's requires, read from its go.mod on the proxy.
// Each require becomes a ">=version" constraint (Go's minimum-version meaning).
func (w *WalkSource) Declared(ctx context.Context, coords []datasource.Coord) (map[string][]expand.Declaration, error) {
	if w.Proxy == nil {
		return nil, nil
	}
	out := make(map[string][]expand.Declaration, len(coords))
	var firstErr error
	for _, c := range coords {
		raw, ok, err := w.Proxy.ModFile(ctx, c.Name, c.Version)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !ok {
			continue // not on the proxy (a replace/local module): a frontier
		}
		_, requires := scanGoMod(raw)
		decls := make([]expand.Declaration, 0, len(requires))
		for _, r := range requires {
			// A module's own go.mod lists its full transitive minimum set in
			// Go 1.17+; take only its DIRECT (non-indirect) requires as edges,
			// so the reconstructed tree mirrors the real import graph rather
			// than fanning every module out from every other.
			if r.indirect {
				continue
			}
			decls = append(decls, expand.Declaration{Name: r.module, Constraint: ">=" + r.version})
		}
		out[c.Key()] = decls
	}
	return out, firstErr
}

// Versions lists a module's tagged versions from the proxy.
func (w *WalkSource) Versions(ctx context.Context, _, name string) ([]string, error) {
	if w.Proxy == nil {
		return nil, nil
	}
	return w.Proxy.Versions(ctx, name)
}

// Satisfies evaluates a ">=version" minimum against a candidate, Go/semver
// style (v-prefix, +incompatible, pseudo-versions all tolerated by semver.Parse).
func (*WalkSource) Satisfies(constraint, version string) (ok, evaluable bool) {
	return semver.Satisfies(constraint, version)
}

// CompareVersions orders two Go versions.
func (*WalkSource) CompareVersions(a, b string) int {
	return semver.Parse(a).Compare(semver.Parse(b))
}

// PrefersLowest reports true: Go's MVS selects the lowest version satisfying all
// the accumulated minimum requirements.
func (*WalkSource) PrefersLowest() bool { return true }

var (
	_ expand.Declarer       = (*WalkSource)(nil)
	_ expand.VersionIndex   = (*WalkSource)(nil)
	_ expand.Presumer       = (*WalkSource)(nil)
	_ expand.LowestResolver = (*WalkSource)(nil)
)
