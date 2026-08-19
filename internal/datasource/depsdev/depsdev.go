// Package depsdev consumes deps.dev's resolved dependency graphs — the external
// service Decision D-01 named for manifest-only inputs. It supplies the ASSERTED
// tier of transitive expansion (D-44): a concrete, real-resolution version for
// every dependency of an observed coordinate, rather than a version this tool
// presumed from a constraint.
//
// Trust posture. deps.dev is a third party. Its answer is stronger than a guess
// (a resolver actually ran) but is not this build's lockfile, so an asserted
// version still may not gate — the same demotion presumed versions get. The
// dependency is also OPT-IN (a CLI flag), because reaching a new external
// service is a policy choice an operator makes, not a default.
package depsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/expand"
)

const maxResponseSize = 16 << 20

// Doer is the minimal HTTP surface, injectable so tests never touch a network.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client resolves coordinates against deps.dev.
type Client struct {
	HTTP    Doer
	Cache   *datasource.Cache
	Offline bool
	Now     func() time.Time
	Stats   datasource.Stats
}

// New returns a Client with sensible defaults.
func New(cache *datasource.Cache, offline bool) *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}, Cache: cache, Offline: offline, Now: time.Now}
}

// Name implements expand.Resolver.
func (*Client) Name() string { return "deps.dev" }

// system maps depSNORT's ecosystem ids to deps.dev's system names. deps.dev has
// no Composer/Packagist system, so composer returns "" and Resolve reports no
// answer — the walk then falls back to the presume tier for those roots.
func system(ecosystem string) string {
	switch ecosystem {
	case "pypi":
		return "pypi"
	case "npm":
		return "npm"
	case "cargo":
		return "cargo"
	case "nuget":
		return "nuget"
	case "gem":
		return "rubygems"
	default:
		return ""
	}
}

func (c *Client) cacheKey(sys, name, version string) string {
	return "depsdev|" + sys + "|" + name + "|" + version
}

// Resolve implements expand.Resolver: it returns the fully resolved transitive
// graph deps.dev computed for the coordinate. ok is false when deps.dev has no
// record (a 404, an unsupported ecosystem, or an offline cold cache), which the
// walk treats as "fall back to presume", not as an error.
func (c *Client) Resolve(ctx context.Context, ecosystem, name, version string) (expand.ResolvedGraph, bool, error) {
	sys := system(ecosystem)
	if sys == "" {
		return expand.ResolvedGraph{}, false, nil
	}
	c.Stats.Queried++

	key := c.cacheKey(sys, name, version)
	if raw, fresh, ok := c.Cache.GetRaw(key); ok && (fresh || c.Offline) {
		rg, ok := parse(raw)
		if ok {
			c.Stats.FromCache++
			return rg, true, nil
		}
	}
	if c.Offline {
		c.Stats.Gaps++
		return expand.ResolvedGraph{}, false, nil
	}

	raw, status, err := c.fetch(ctx, sys, name, version)
	if err != nil {
		c.Stats.Gaps++
		return expand.ResolvedGraph{}, false, err
	}
	if status == http.StatusNotFound {
		c.Stats.NotFound++
		return expand.ResolvedGraph{}, false, nil
	}
	if status != http.StatusOK {
		c.Stats.Gaps++
		return expand.ResolvedGraph{}, false, fmt.Errorf("deps.dev: %s/%s@%s: status %d", sys, name, version, status)
	}
	rg, ok := parse(raw)
	if !ok {
		c.Stats.Gaps++
		return expand.ResolvedGraph{}, false, fmt.Errorf("deps.dev: %s/%s@%s: unparseable response", sys, name, version)
	}
	c.Stats.FromNet++
	now := c.Now
	if now == nil {
		now = time.Now
	}
	_ = c.Cache.PutRaw(key, raw, now())
	return rg, true, nil
}

func (c *Client) fetch(ctx context.Context, sys, name, version string) ([]byte, int, error) {
	u := "https://api.deps.dev/v3/systems/" + url.PathEscape(sys) +
		"/packages/" + url.PathEscape(name) +
		"/versions/" + url.PathEscape(version) + ":dependencies"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("deps.dev: %s/%s@%s: %w", sys, name, version, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	return body, resp.StatusCode, err
}

// depsdevResponse is the subset of the :dependencies response we read.
type depsdevResponse struct {
	Nodes []struct {
		VersionKey struct {
			System  string `json:"system"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"versionKey"`
		Relation string `json:"relation"` // SELF | DIRECT | INDIRECT
	} `json:"nodes"`
	Edges []struct {
		FromNode int `json:"fromNode"`
		ToNode   int `json:"toNode"`
	} `json:"edges"`
}

// parse converts the response into an expand.ResolvedGraph, translating
// deps.dev's uppercase system names back to depSNORT's ecosystem ids. A node
// whose system this tool does not model is kept (so edges still resolve) but
// carries its lowercased system verbatim.
func parse(raw []byte) (expand.ResolvedGraph, bool) {
	var resp depsdevResponse
	if json.Unmarshal(raw, &resp) != nil {
		return expand.ResolvedGraph{}, false
	}
	if len(resp.Nodes) == 0 {
		return expand.ResolvedGraph{}, false
	}
	rg := expand.ResolvedGraph{Nodes: make([]expand.ResolvedRef, len(resp.Nodes))}
	for i, n := range resp.Nodes {
		rg.Nodes[i] = expand.ResolvedRef{
			Ecosystem: ecosystemOf(n.VersionKey.System),
			Name:      n.VersionKey.Name,
			Version:   n.VersionKey.Version,
		}
	}
	for _, e := range resp.Edges {
		rg.Edges = append(rg.Edges, expand.ResolvedEdge{From: e.FromNode, To: e.ToNode})
	}
	return rg, true
}

func ecosystemOf(system string) string {
	switch system {
	case "PYPI":
		return "pypi"
	case "NPM":
		return "npm"
	case "CARGO":
		return "cargo"
	case "NUGET":
		return "nuget"
	case "RUBYGEMS":
		return "gem"
	default:
		return lower(system)
	}
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

var _ expand.Resolver = (*Client)(nil)
