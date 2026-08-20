package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// CargoDepsClient fetches per-version dependency metadata from the crates.io
// API — the same public, zero-execution metadata the release-history Client
// reads, a different endpoint. Its own type for the same reason PyPIDepsClient
// is: the result shape (dependencies, not a ReleaseHistory) and the cache key
// (per exact version) do not fit the Client/Spec contract. Both share the
// coordFetcher plumbing.
type CargoDepsClient struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// NewCargoDeps returns a CargoDepsClient with sensible defaults.
func NewCargoDeps(cache *datasource.Cache, offline bool) *CargoDepsClient {
	return &CargoDepsClient{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Cache:   cache,
		Offline: offline,
		Now:     time.Now,
	}
}

// Name identifies this source in coverage reports.
func (c *CargoDepsClient) Name() string { return "cargo-dependencies" }

func (c *CargoDepsClient) cacheKey(coord datasource.Coord) string {
	return "cargo-dependencies|" + coord.Name + "|" + coord.Version
}

// CargoRequirement is one declared dependency with its version requirement.
type CargoRequirement struct {
	Name     string
	Req      string // raw crates.io requirement, e.g. "^0.2" or ">=1.0, <2.0"
	Optional bool
	// Kind is the crates.io dependency kind: "normal" or "build" (dev is dropped
	// upstream). A build dependency runs at compile time (build.rs) — the vector
	// the yank-lure attack introduced (proc-macro1 as a NEW build-dep), so VC-012
	// diffs build-deps specifically (OPU-26).
	Kind string
}

// IntroducedBuildDeps returns the names of BUILD dependencies present in newest
// but not in baseline — the "new build-dep vs the last-good release" tell of a
// yank-lure (arrayref 0.3.10 added proc-macro1 as a build dep 0.3.9 never had).
// Normal-kind deps are ignored: a new build-time dependency is the compile-time
// code-execution vector, and adding one is far rarer and more suspicious than a
// new normal dependency. Deterministic order (D-13).
func IntroducedBuildDeps(baseline, newest []CargoRequirement) []string {
	had := map[string]bool{}
	for _, d := range baseline {
		if d.Kind == "build" {
			had[d.Name] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range newest {
		if d.Kind != "build" || had[d.Name] || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

// Requirements returns each coordinate's dependencies WITH their requirements,
// keyed by datasource.Coord.Key(). A coordinate absent from the map was not
// read (distinct from one that declares nothing), which the walk counts as a
// frontier.
//
// # What is and is not an edge here
//
// crates.io tags every dependency with a kind. "normal" and "build" are both
// included: a build dependency runs at compile time (build.rs), which for a
// supply-chain tool is not a lesser edge but a MORE dangerous one — it is the
// exact vector D-02's install-time subgraph exists to model. "dev"
// dependencies are excluded: Cargo compiles a crate's dev-dependencies only for
// that crate's own tests and examples, never for a crate that depends on it, so
// treating them as present would inflate every crate's subtree with test-only
// code no build of the consumer pulls. optional (feature-gated) dependencies
// are marked Optional, the might-install edge the default walk drops.
func (c *CargoDepsClient) Requirements(ctx context.Context, coords []datasource.Coord) (map[string][]CargoRequirement, error) {
	out, stats, err := fetchCoords(coordFetcher{
		cache: c.Cache, offline: c.Offline, now: c.Now,
		cacheKey: c.cacheKey, fetch: c.fetch,
	}, ctx, coords, parseCargoDeps)
	c.Stats = stats
	return out, err
}

func (c *CargoDepsClient) fetch(ctx context.Context, coord datasource.Coord) ([]byte, error) {
	u := "https://crates.io/api/v1/crates/" + url.PathEscape(coord.Name) + "/" + url.PathEscape(coord.Version) + "/dependencies"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	// crates.io requires a descriptive User-Agent or returns 403.
	req.Header.Set("User-Agent", "depsnort (supply-chain IDS)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cargo-dependencies: %s@%s: %w", coord.Name, coord.Version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("cargo-dependencies: %s@%s: %w", coord.Name, coord.Version, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("cargo-dependencies: %s@%s: status %d: %s", coord.Name, coord.Version, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}

type cargoDepsResponse struct {
	Dependencies []struct {
		CrateID  string `json:"crate_id"`
		Req      string `json:"req"`
		Kind     string `json:"kind"`
		Optional bool   `json:"optional"`
	} `json:"dependencies"`
}

// parseCargoDeps keeps normal and build dependencies, drops dev, and reports
// nothing as unparsed (crates.io gives a structured req, not free text to fail
// on) — the int is present only to satisfy the shared coordFetcher contract.
func parseCargoDeps(raw []byte) ([]CargoRequirement, int, error) {
	var resp cargoDepsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, 0, fmt.Errorf("cargo-dependencies: parsing response: %w", err)
	}
	var reqs []CargoRequirement
	for _, d := range resp.Dependencies {
		if d.CrateID == "" || d.Kind == "dev" {
			continue
		}
		kind := d.Kind
		if kind == "" {
			kind = "normal" // crates.io omits kind for plain deps
		}
		reqs = append(reqs, CargoRequirement{Name: d.CrateID, Req: d.Req, Optional: d.Optional, Kind: kind})
	}
	return reqs, 0, nil
}
