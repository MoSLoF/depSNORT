// Package registry is the shared fetch/cache/concurrency machinery for
// ecosystem registry metadata. Each ecosystem provides a Spec; the Client
// handles everything else (cache pass, bounded-parallel network fetch, stats,
// error collection). Only metadata is fetched — never a package archive
// (Decision D-04).
package registry

import (
	"context"
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

const concurrency = 8

const maxResponseSize = 50 * 1024 * 1024

// ErrNotFound reports that the registry has no record of a package (HTTP 404).
var ErrNotFound = errors.New("package not found on registry")

// Doer is the minimal HTTP surface; injectable so tests never touch a network.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Spec defines the per-ecosystem differences. Everything else is shared.
type Spec struct {
	SourceName string // e.g. "rubygems-registry" — appears in coverage reports
	Eco        string // e.g. "gem" — matches Node.Ecosystem
	CacheTag   string // e.g. "gem" — cache key prefix
	Endpoint   string // default registry base URL

	// BuildURL returns the full URL for a package name.
	BuildURL func(endpoint, name string) string

	// SetHeaders adds any required headers to the request. May be nil.
	SetHeaders func(req *http.Request)

	// Parse turns raw response bytes into a ReleaseHistory.
	Parse func(name string, raw []byte) (*datasource.ReleaseHistory, error)
}

// Client fetches release history using a Spec's ecosystem-specific logic and
// the shared cache/concurrency/stats machinery.
type Client struct {
	Spec    Spec
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// New returns a Client with sensible defaults.
func New(spec Spec, cache *datasource.Cache, offline bool) *Client {
	return &Client{
		Spec:    spec,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Cache:   cache,
		Offline: offline,
		Now:     time.Now,
	}
}

func (c *Client) Name() string               { return c.Spec.SourceName }
func (c *Client) Ecosystem() string          { return c.Spec.Eco }
func (c *Client) GetStats() datasource.Stats { return c.Stats }

func (c *Client) cacheKey(name string) string {
	return c.Spec.CacheTag + "|" + name + "|versions"
}

// Histories fetches release history for each unique package name. Results are
// keyed by package name. Packages that cannot be fetched are omitted and
// counted as gaps.
func (c *Client) Histories(ctx context.Context, names []string) (map[string]*datasource.ReleaseHistory, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out := make(map[string]*datasource.ReleaseHistory, len(names))
	c.Stats = datasource.Stats{Queried: len(names), Offline: c.Offline}

	var misses []string
	for _, name := range names {
		if raw, fresh, ok := c.Cache.GetRaw(c.cacheKey(name)); ok && (fresh || c.Offline) {
			if h, err := c.Spec.Parse(name, raw); err == nil {
				out[name] = h
				c.Stats.FromCache++
				continue
			}
		}
		if c.Offline {
			c.Stats.Gaps++
			continue
		}
		misses = append(misses, name)
	}
	if len(misses) == 0 {
		return out, nil
	}

	type result struct {
		name string
		h    *datasource.ReleaseHistory
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
			if err != nil {
				results[i] = result{name: name, err: err}
				return
			}
			h, err := c.Spec.Parse(name, raw)
			results[i] = result{name: name, h: h, raw: raw, err: err}
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
		out[r.name] = r.h
		c.Stats.FromNet++
		_ = c.Cache.PutRaw(c.cacheKey(r.name), r.raw, now())
	}
	if len(errsBy) > 0 {
		sorted := make([]string, 0, len(errsBy))
		for n := range errsBy {
			sorted = append(sorted, n)
		}
		sort.Strings(sorted)
		return out, errsBy[sorted[0]]
	}
	return out, nil
}

func (c *Client) fetch(ctx context.Context, name string) ([]byte, error) {
	endpoint := c.Spec.Endpoint
	u := c.Spec.BuildURL(endpoint, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.Spec.SetHeaders != nil {
		c.Spec.SetHeaders(req)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", c.Spec.CacheTag, name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %s: %w", c.Spec.CacheTag, name, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("%s: %s: status %d: %s", c.Spec.CacheTag, name, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}
