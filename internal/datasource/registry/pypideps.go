package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/pep508"
	"ihbv.io/depsnort/internal/purl"
)

// PyPIDepsClient fetches per-release requires_dist metadata from PyPI's JSON
// API — the same public, zero-execution metadata Client uses for release
// history, just a different field. Kept as its own type rather than another
// Spec because its result shape (dependency names, not a ReleaseHistory) and
// its cache key (per exact pinned version, not per package name) don't fit
// the Client/Spec contract.
type PyPIDepsClient struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// NewPyPIDeps returns a PyPIDepsClient with sensible defaults.
func NewPyPIDeps(cache *datasource.Cache, offline bool) *PyPIDepsClient {
	return &PyPIDepsClient{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Cache:   cache,
		Offline: offline,
		Now:     time.Now,
	}
}

// Name identifies this source in coverage reports.
func (c *PyPIDepsClient) Name() string { return "pypi-requires-dist" }

func (c *PyPIDepsClient) cacheKey(coord datasource.Coord) string {
	return "pypi-requires-dist|" + coord.Name + "|" + coord.Version
}

// RequiresDist fetches https://pypi.org/pypi/{name}/{version}/json for each
// coordinate — the VERSIONED endpoint for the exact pinned release, not
// "latest": a different release can have an entirely different dependency
// list, so anything else would misattribute edges. Results are keyed by
// datasource.Coord.Key() so a caller holding a *graph.Node can look its
// entry up without depending on this package's internal cache-key format.
//
// Each info.requires_dist entry is reduced, via pep508.Split, to a plain,
// PEP-503-normalized dependency name — the same normalization every
// graph.Node.Name already carries, so downstream name-membership checks need
// no re-normalization of their own. An entry whose marker proves it is
// conditioned on an extra (pep508.GatedByExtra) is dropped: this tool never
// knows which extras a flat pin actually requested, so it cannot claim that
// edge exists.
//
// A coordinate whose fetch fails is omitted from the result map and counted
// in Stats.Gaps — mirroring Client.Histories's contract exactly, including
// the offline-cold-cache-is-a-gap-not-an-error and 404-is-not-an-error rules.
// Requirements returns each coordinate's dependencies WITH version specifiers,
// for the Nth-layer walk. It shares fetch, cache, concurrency, and Stats with
// RequiresDist through fetchParsed; the two differ only in the parse.
func (c *PyPIDepsClient) Requirements(ctx context.Context, coords []datasource.Coord) (map[string][]Requirement, error) {
	return fetchParsed(c, ctx, coords, parseRequirements)
}

// RequiresDist returns dependency NAMES only — all D-01 re-parenting needs.
func (c *PyPIDepsClient) RequiresDist(ctx context.Context, coords []datasource.Coord) (map[string][]string, error) {
	return fetchParsed(c, ctx, coords, parseRequiresDist)
}

func fetchParsed[T any](c *PyPIDepsClient, ctx context.Context, coords []datasource.Coord, parse func([]byte) ([]T, int, error)) (map[string][]T, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out := make(map[string][]T, len(coords))
	c.Stats = datasource.Stats{Queried: len(coords), Offline: c.Offline}

	var misses []datasource.Coord
	for _, coord := range coords {
		key := c.cacheKey(coord)
		if raw, fresh, ok := c.Cache.GetRaw(key); ok && (fresh || c.Offline) {
			if items, unparsed, err := parse(raw); err == nil {
				out[coord.Key()] = items
				c.Stats.FromCache++
				c.Stats.UnparsedEntries += unparsed
				continue
			}
		}
		if c.Offline {
			c.Stats.Gaps++
			continue
		}
		misses = append(misses, coord)
	}
	if len(misses) == 0 {
		return out, nil
	}

	type result struct {
		coord    datasource.Coord
		items    []T
		unparsed int
		raw      []byte
		err      error
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		errsBy  = map[string]error{}
		sem     = make(chan struct{}, concurrency)
		results = make([]result, len(misses))
	)
	for i, coord := range misses {
		wg.Add(1)
		go func(i int, coord datasource.Coord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			raw, err := c.fetch(ctx, coord)
			if err != nil {
				results[i] = result{coord: coord, err: err}
				return
			}
			items, unparsed, err := parse(raw)
			results[i] = result{coord: coord, items: items, unparsed: unparsed, raw: raw, err: err}
		}(i, coord)
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
			errsBy[r.coord.Key()] = r.err
			mu.Unlock()
			continue
		}
		out[r.coord.Key()] = r.items
		c.Stats.FromNet++
		c.Stats.UnparsedEntries += r.unparsed
		_ = c.Cache.PutRaw(c.cacheKey(r.coord), r.raw, now())
	}
	if len(errsBy) > 0 {
		sorted := make([]string, 0, len(errsBy))
		for k := range errsBy {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		return out, errsBy[sorted[0]]
	}
	return out, nil
}

func (c *PyPIDepsClient) fetch(ctx context.Context, coord datasource.Coord) ([]byte, error) {
	u := "https://pypi.org/pypi/" + url.PathEscape(coord.Name) + "/" + url.PathEscape(coord.Version) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pypi-requires-dist: %s@%s: %w", coord.Name, coord.Version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("pypi-requires-dist: %s@%s: %w", coord.Name, coord.Version, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("pypi-requires-dist: %s@%s: status %d: %s", coord.Name, coord.Version, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}

type pypiDepsResponse struct {
	Info struct {
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
}

// Requirement is one requires_dist entry with its version specifier preserved.
// RequiresDist reduces these to names (all D-01 reconstruction needs); the
// Nth-layer walk needs the specifier to presume a version, so it reads these.
type Requirement struct {
	Name      string // PEP 503 normalized
	Specifier string // raw, e.g. ">=1.21,<2.0"; "" when unconstrained
	Marker    string // environment marker, e.g. extra == "async"
}

// parseRequirements extracts info.requires_dist into structured entries,
// preserving the specifier. Unparseable entries are counted, not dropped
// silently (D-24), and extras-gated ones are excluded exactly as
// parseRequiresDist excludes them, so the two views of the same response never
// disagree about which edges exist.
func parseRequirements(raw []byte) (reqs []Requirement, unparsed int, err error) {
	var resp pypiDepsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, 0, fmt.Errorf("pypi-requires-dist: parsing response: %w", err)
	}
	for _, entry := range resp.Info.RequiresDist {
		name, spec, marker := pep508.SplitSpecifier(entry)
		if name == "" {
			unparsed++
			continue
		}
		if pep508.GatedByExtra(marker) {
			continue
		}
		reqs = append(reqs, Requirement{Name: purl.NormalizePyPI(name), Specifier: spec, Marker: marker})
	}
	return reqs, unparsed, nil
}

// parseRequiresDist extracts info.requires_dist and reduces each PEP 508
// requirement string to a plain, PEP-503-normalized dependency name,
// dropping anything extras-gated (see RequiresDist's doc comment for why).
// It also reports how many entries could not be parsed at all. That count is
// kept DISTINCT from the extras-gated skip below: an extras-gated entry is a
// deliberate, documented exclusion, whereas an unparseable one is a dependency
// edge silently missing from the graph. Conflating them — as one combined
// `name == "" || GatedByExtra(marker)` skip did — hid the second behind the
// first (Decision D-24).
func parseRequiresDist(raw []byte) (names []string, unparsed int, err error) {
	reqs, unparsed, err := parseRequirements(raw)
	if err != nil {
		return nil, 0, err
	}
	for _, r := range reqs {
		names = append(names, r.Name)
	}
	return names, unparsed, nil
}
