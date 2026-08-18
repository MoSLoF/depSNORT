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

// ComposerDepsClient reads per-version `require` maps from the Packagist v2
// metadata endpoint — the same document the release-history Client reads for
// versions, a different field. Because that document holds every version's
// requirements, it batches by name (like npmreg and the NuGet deps client),
// not by coordinate.
type ComposerDepsClient struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// NewComposerDeps returns a ComposerDepsClient with sensible defaults.
func NewComposerDeps(cache *datasource.Cache, offline bool) *ComposerDepsClient {
	return &ComposerDepsClient{HTTP: &http.Client{Timeout: 30 * time.Second}, Cache: cache, Offline: offline, Now: time.Now}
}

// Name identifies this source in coverage reports.
func (c *ComposerDepsClient) Name() string { return "composer-dependencies" }

func (c *ComposerDepsClient) cacheKey(name string) string {
	return "composer-dependencies|" + strings.ToLower(name) + "|p2"
}

// ComposerRequirement is one declared dependency with its Composer constraint.
type ComposerRequirement struct {
	Name       string
	Constraint string
}

// Requirements returns each package version's `require` entries, keyed by
// datasource.Coord.Key(). Platform requirements — php, hhvm, ext-*, lib-*,
// composer-* — are excluded: they constrain the runtime, not a package this
// tool can resolve or scan, and following them would 404 every time.
func (c *ComposerDepsClient) Requirements(ctx context.Context, coords []datasource.Coord) (map[string][]ComposerRequirement, error) {
	names := make([]string, 0, len(coords))
	seen := map[string]bool{}
	for _, co := range coords {
		l := strings.ToLower(co.Name)
		if !seen[l] {
			seen[l] = true
			names = append(names, co.Name)
		}
	}

	byName := map[string]map[string][]ComposerRequirement{}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	c.Stats = datasource.Stats{Queried: len(coords), Offline: c.Offline}

	var misses []string
	for _, name := range names {
		if raw, fresh, ok := c.Cache.GetRaw(c.cacheKey(name)); ok && (fresh || c.Offline) {
			byName[strings.ToLower(name)] = parseComposerRequires(name, raw)
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
			byName[strings.ToLower(r.name)] = parseComposerRequires(r.name, r.raw)
			c.Stats.FromNet++
			_ = c.Cache.PutRaw(c.cacheKey(r.name), r.raw, now())
		}
		if len(errsBy) > 0 {
			sorted := make([]string, 0, len(errsBy))
			for k := range errsBy {
				sorted = append(sorted, k)
			}
			sort.Strings(sorted)
			return foldComposer(coords, byName), errsBy[sorted[0]]
		}
	}
	return foldComposer(coords, byName), nil
}

func foldComposer(coords []datasource.Coord, byName map[string]map[string][]ComposerRequirement) map[string][]ComposerRequirement {
	out := make(map[string][]ComposerRequirement, len(coords))
	for _, co := range coords {
		versions, ok := byName[strings.ToLower(co.Name)]
		if !ok {
			continue
		}
		if deps, ok := versions[co.Version]; ok {
			out[co.Key()] = deps
		}
	}
	return out
}

func (c *ComposerDepsClient) fetch(ctx context.Context, name string) ([]byte, error) {
	u := "https://repo.packagist.org/p2/" + name + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("composer-dependencies: %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("composer-dependencies: %s: %w", name, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("composer-dependencies: %s: status %d: %s", name, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}

type composerP2 struct {
	Packages map[string][]struct {
		Version string            `json:"version"`
		Require map[string]string `json:"require"`
	} `json:"packages"`
}

func parseComposerRequires(name string, raw []byte) map[string][]ComposerRequirement {
	var p composerP2
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	out := map[string][]ComposerRequirement{}
	for _, versions := range p.Packages {
		for _, v := range versions {
			if v.Version == "" {
				continue
			}
			// Packagist prefixes tags with "v" in the version field sometimes;
			// the lockfile records the bare form, so normalize for the key.
			key := strings.TrimPrefix(v.Version, "v")
			var reqs []ComposerRequirement
			for dep, constraint := range v.Require {
				if isPlatformPackage(dep) {
					continue
				}
				reqs = append(reqs, ComposerRequirement{Name: dep, Constraint: constraint})
			}
			out[key] = reqs
			out[v.Version] = reqs // also index the raw form, in case the lockfile kept the "v"
		}
	}
	return out
}

// isPlatformPackage reports whether a Composer require key names the runtime
// rather than an installable package: php, hhvm, extensions, and libraries.
func isPlatformPackage(name string) bool {
	l := strings.ToLower(name)
	switch {
	case l == "php", l == "hhvm":
		return true
	case strings.HasPrefix(l, "ext-"), strings.HasPrefix(l, "lib-"), strings.HasPrefix(l, "composer-"):
		return true
	case !strings.Contains(l, "/"):
		// Every real Composer package is "vendor/name"; a key without a slash
		// that is not one of the above is a platform token we do not model.
		return true
	}
	return false
}
