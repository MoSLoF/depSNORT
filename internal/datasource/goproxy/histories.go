package goproxy

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// concurrency bounds simultaneous per-version .info fetches. Go's proxy has no
// bulk publish-time endpoint, so a module's release history is one request per
// version; this keeps a wide module from opening hundreds of connections at once.
const concurrency = 12

// Ecosystem implements datasource.RegistrySource — Go module nodes carry
// Ecosystem "gomod".
func (*Client) Ecosystem() string { return "gomod" }

// GetStats implements datasource.RegistrySource.
func (c *Client) GetStats() datasource.Stats { return c.Stats }

// Histories implements datasource.RegistrySource: it builds each module's
// release history (version + publish time) so the temporal axis (VC-004
// dormancy, VC-005 burst) can reason about Go modules like any other ecosystem.
//
// The Go proxy exposes no bulk timestamp endpoint, so this is the version list
// plus one @v/{version}.info fetch per version. Both are immutable once
// published and cached with a long TTL, so the cost is paid once per module and
// re-runs are free. A module the proxy has no record of (a replace directive, a
// private module) yields no history rather than an error — disclosed as a gap,
// not a failure.
func (c *Client) Histories(ctx context.Context, names []string) (map[string]*datasource.ReleaseHistory, error) {
	out := make(map[string]*datasource.ReleaseHistory, len(names))
	var firstErr error
	for _, name := range names {
		versions, err := c.Versions(ctx, name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(versions) == 0 {
			continue
		}
		h := &datasource.ReleaseHistory{Package: name, Ecosystem: "gomod"}

		type res struct {
			version string
			t       time.Time
			ok      bool
		}
		results := make([]res, len(versions))
		var wg sync.WaitGroup
		sem := make(chan struct{}, concurrency)
		for i, v := range versions {
			wg.Add(1)
			go func(i int, v string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				t, ok := c.info(ctx, name, v)
				results[i] = res{version: v, t: t, ok: ok}
			}(i, v)
		}
		wg.Wait()

		for _, r := range results {
			if r.ok {
				h.Releases = append(h.Releases, datasource.Release{Version: r.version, Published: r.t})
			}
		}
		h.Sort()
		out[name] = h
	}
	return out, firstErr
}

// info fetches a version's publish time from @v/{version}.info.
func (c *Client) info(ctx context.Context, module, version string) (time.Time, bool) {
	raw, ok, err := c.get(ctx, escapeModule(module)+"/@v/"+escapeVersion(version)+".info", "info|"+module+"@"+version)
	if err != nil || !ok {
		return time.Time{}, false
	}
	var doc struct {
		Version string `json:"Version"`
		Time    string `json:"Time"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Time == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, doc.Time)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

var _ datasource.RegistrySource = (*Client)(nil)
