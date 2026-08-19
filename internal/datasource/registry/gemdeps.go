package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// GemDepsClient reads per-version runtime dependencies from the RubyGems v2 API
// — public, zero-execution metadata, per exact version. Its own type for the
// same reason the PyPI/Cargo deps clients are, and it shares their coordFetcher
// plumbing.
type GemDepsClient struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// NewGemDeps returns a GemDepsClient with sensible defaults.
func NewGemDeps(cache *datasource.Cache, offline bool) *GemDepsClient {
	return &GemDepsClient{HTTP: &http.Client{Timeout: 30 * time.Second}, Cache: cache, Offline: offline, Now: time.Now}
}

// Name identifies this source in coverage reports.
func (c *GemDepsClient) Name() string { return "rubygems-dependencies" }

func (c *GemDepsClient) cacheKey(coord datasource.Coord) string {
	return "rubygems-dependencies|" + coord.Name + "|" + coord.Version
}

// GemRequirement is one declared dependency with its RubyGems requirement.
type GemRequirement struct {
	Name string
	Req  string // e.g. "~> 1.2" or ">= 1.0, < 2.0"
}

// Requirements returns each gem version's RUNTIME dependencies with their
// requirements, keyed by datasource.Coord.Key(). Development dependencies are
// excluded: Bundler installs a gem's development group only for that gem's own
// work, never for a gem that depends on it, so treating them as present would
// inflate every gem's subtree with test/build tooling no consumer pulls.
func (c *GemDepsClient) Requirements(ctx context.Context, coords []datasource.Coord) (map[string][]GemRequirement, error) {
	out, stats, err := fetchCoords(coordFetcher{
		cache: c.Cache, offline: c.Offline, now: c.Now,
		cacheKey: c.cacheKey, fetch: c.fetch,
	}, ctx, coords, parseGemDeps)
	c.Stats = stats
	return out, err
}

func (c *GemDepsClient) fetch(ctx context.Context, coord datasource.Coord) ([]byte, error) {
	u := "https://rubygems.org/api/v2/rubygems/" + url.PathEscape(coord.Name) + "/versions/" + url.PathEscape(coord.Version) + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rubygems-dependencies: %s@%s: %w", coord.Name, coord.Version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("rubygems-dependencies: %s@%s: %w", coord.Name, coord.Version, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("rubygems-dependencies: %s@%s: status %d: %s", coord.Name, coord.Version, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}

type gemVersionDetail struct {
	Dependencies struct {
		Runtime []struct {
			Name         string `json:"name"`
			Requirements string `json:"requirements"`
		} `json:"runtime"`
	} `json:"dependencies"`
}

func parseGemDeps(raw []byte) ([]GemRequirement, int, error) {
	var d gemVersionDetail
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, 0, fmt.Errorf("rubygems-dependencies: parsing response: %w", err)
	}
	var reqs []GemRequirement
	for _, dep := range d.Dependencies.Runtime {
		if dep.Name == "" {
			continue
		}
		reqs = append(reqs, GemRequirement{Name: dep.Name, Req: dep.Requirements})
	}
	return reqs, 0, nil
}
