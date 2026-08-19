package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// NuGetDepsClient reads per-version dependency groups from the NuGet
// registration index — the same document the release-history Client reads for
// versions, a different field of it. Its own type because the result shape
// (dependencies, not a ReleaseHistory) does not fit the Client/Spec contract,
// and because the registration index is fetched per PACKAGE (all versions in
// one document), so it batches by name like npmreg, not by coordinate like the
// PyPI/Cargo deps clients.
type NuGetDepsClient struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// NewNuGetDeps returns a NuGetDepsClient with sensible defaults.
func NewNuGetDeps(cache *datasource.Cache, offline bool) *NuGetDepsClient {
	return &NuGetDepsClient{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Cache:   cache,
		Offline: offline,
		Now:     time.Now,
	}
}

// Name identifies this source in coverage reports.
func (c *NuGetDepsClient) Name() string { return "nuget-dependencies" }

func (c *NuGetDepsClient) cacheKey(name string) string {
	return "nuget-dependencies|" + strings.ToLower(name) + "|regindex"
}

// NuGetRequirement is one declared dependency with its version range.
type NuGetRequirement struct {
	Name  string
	Range string // NuGet range notation, e.g. "[1.0.0, )" or "1.0.0"
}

// Requirements returns each coordinate's dependencies WITH their ranges, keyed
// by datasource.Coord.Key(). A coordinate absent from the map was not read
// (distinct from one that declares nothing), which the walk counts as a
// frontier.
//
// # Target frameworks
//
// A NuGet package declares dependencies per target framework (dependencyGroups).
// depSNORT does not know the consuming project's framework, so it takes the
// UNION across groups: any of them could be the one restored, and a
// supply-chain walk wants to see every dependency that any framework would
// pull. A dependency appearing in several groups is deduped by id, keeping the
// first range seen.
func (c *NuGetDepsClient) Requirements(ctx context.Context, coords []datasource.Coord) (map[string][]NuGetRequirement, error) {
	names := make([]string, 0, len(coords))
	seen := map[string]bool{}
	for _, co := range coords {
		lname := strings.ToLower(co.Name)
		if !seen[lname] {
			seen[lname] = true
			names = append(names, co.Name)
		}
	}

	// byNameVersion[lowerName][version] = deps
	byName := map[string]map[string][]NuGetRequirement{}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	c.Stats = datasource.Stats{Queried: len(coords), Offline: c.Offline}

	var misses []string
	for _, name := range names {
		if raw, fresh, ok := c.Cache.GetRaw(c.cacheKey(name)); ok && (fresh || c.Offline) {
			byName[strings.ToLower(name)] = parseNuGetDepGroups(raw)
			c.Stats.FromCache++
			continue
		}
		if c.Offline {
			c.Stats.Gaps++
			continue
		}
		misses = append(misses, name)
	}

	if len(misses) > 0 {
		type result struct {
			name string
			raw  []byte
			err  error
		}
		var (
			mu      sync.Mutex
			wg      sync.WaitGroup
			errsBy  = map[string]error{}
			sem     = make(chan struct{}, concurrency)
			results = make([]result, len(misses))
		)
		for i, name := range misses {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				raw, err := c.fetch(ctx, name)
				results[i] = result{name: name, raw: raw, err: err}
			}(i, name)
		}
		wg.Wait()
		for _, r := range results {
			if r.err != nil {
				if errors.Is(r.err, ErrNotFound) {
					c.Stats.NotFound++
					continue
				}
				c.Stats.Gaps++
				mu.Lock()
				errsBy[r.name] = r.err
				mu.Unlock()
				continue
			}
			byName[strings.ToLower(r.name)] = parseNuGetDepGroups(r.raw)
			c.Stats.FromNet++
			_ = c.Cache.PutRaw(c.cacheKey(r.name), r.raw, now())
		}
		if len(errsBy) > 0 {
			sorted := make([]string, 0, len(errsBy))
			for k := range errsBy {
				sorted = append(sorted, k)
			}
			sort.Strings(sorted)
			// Fold results collected so far, then surface the error.
			return foldNuGet(coords, byName), errsBy[sorted[0]]
		}
	}
	return foldNuGet(coords, byName), nil
}

// foldNuGet maps the per-name/per-version deps back onto the requested coords.
func foldNuGet(coords []datasource.Coord, byName map[string]map[string][]NuGetRequirement) map[string][]NuGetRequirement {
	out := make(map[string][]NuGetRequirement, len(coords))
	for _, co := range coords {
		versions, ok := byName[strings.ToLower(co.Name)]
		if !ok {
			continue // package not read: a frontier
		}
		if deps, ok := versions[co.Version]; ok {
			out[co.Key()] = deps
		}
		// A version absent from the index is also unread; leaving it out of the
		// map keeps it a frontier rather than a confident empty.
	}
	return out
}

func (c *NuGetDepsClient) fetch(ctx context.Context, name string) ([]byte, error) {
	u := "https://api.nuget.org/v3/registration5-gz-semver2/" + strings.ToLower(name) + "/index.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nuget-dependencies: %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("nuget-dependencies: %s: %w", name, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("nuget-dependencies: %s: status %d: %s", name, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}

type nugetDepsIndex struct {
	Items []struct {
		Items []struct {
			CatalogEntry struct {
				Version          string `json:"version"`
				DependencyGroups []struct {
					Dependencies []struct {
						ID    string `json:"id"`
						Range string `json:"range"`
					} `json:"dependencies"`
				} `json:"dependencyGroups"`
			} `json:"catalogEntry"`
		} `json:"items"`
	} `json:"items"`
}

// parseNuGetDepGroups reads inlined registration leaves into per-version deps,
// unioning dependency groups and deduping by id. Leaves that are not inlined
// (a paged index for a very popular package) contribute no versions here, so
// those versions stay unread — a frontier, not a confident empty.
func parseNuGetDepGroups(raw []byte) map[string][]NuGetRequirement {
	var idx nugetDepsIndex
	if json.Unmarshal(raw, &idx) != nil {
		return nil
	}
	out := map[string][]NuGetRequirement{}
	for _, page := range idx.Items {
		for _, leaf := range page.Items {
			ce := leaf.CatalogEntry
			if ce.Version == "" {
				continue
			}
			seen := map[string]bool{}
			var reqs []NuGetRequirement
			for _, grp := range ce.DependencyGroups {
				for _, dep := range grp.Dependencies {
					if dep.ID == "" {
						continue
					}
					key := strings.ToLower(dep.ID)
					if seen[key] {
						continue
					}
					seen[key] = true
					reqs = append(reqs, NuGetRequirement{Name: dep.ID, Range: dep.Range})
				}
			}
			out[ce.Version] = reqs
		}
	}
	return out
}
