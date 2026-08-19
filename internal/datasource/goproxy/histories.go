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

		// Each version's .info is fetched concurrently, but a fetch mutates no
		// shared Client state — every goroutine writes only its own results slot
		// (the coordfetch pattern). Stats accounting and cache writes are folded
		// in serially after the wait, so the -race detector sees no shared write.
		type res struct {
			version string
			fr      fetchResult
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
				fr := c.fetch(ctx, escapeModule(name)+"/@v/"+escapeVersion(v)+".info", "info|"+name+"@"+v)
				t, ok := parseInfoTime(fr)
				results[i] = res{version: v, fr: fr, t: t, ok: ok}
			}(i, v)
		}
		wg.Wait()

		for _, r := range results {
			c.record(r.fr)
			if r.ok {
				h.Releases = append(h.Releases, datasource.Release{Version: r.version, Published: r.t})
			}
		}
		h.Sort()
		out[name] = h
	}
	return out, firstErr
}

// parseInfoTime extracts the publish time from an @v/{version}.info fetch. It is
// pure — it reads only the fetch's own bytes — so it is safe to call from the
// concurrent goroutines in Histories.
func parseInfoTime(fr fetchResult) (time.Time, bool) {
	if fr.err != nil || !fr.ok {
		return time.Time{}, false
	}
	var doc struct {
		Version string `json:"Version"`
		Time    string `json:"Time"`
	}
	if json.Unmarshal(fr.raw, &doc) != nil || doc.Time == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, doc.Time)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

var _ datasource.RegistrySource = (*Client)(nil)
