// Package goproxy reads Go module metadata from the Go module proxy
// (proxy.golang.org) — the public, zero-execution source Go itself uses. It
// supplies the transitive-expansion seam for Go modules (D-44): a module's
// version list and its own go.mod (whose require block is its dependency set).
//
// Nothing here runs `go` (D-04); it is two HTTP GETs against the proxy's
// documented endpoints:
//
//	GET /{module}/@v/list            -> newline-separated tagged versions
//	GET /{module}/@v/{version}.mod   -> that version's go.mod text
package goproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

const maxResponseSize = 8 << 20

// Doer is the minimal HTTP surface, injected so tests never touch a network.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client fetches Go module metadata.
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

// Name identifies this source in coverage reports.
func (*Client) Name() string { return "go-proxy" }

// Versions returns a module's tagged versions (the proxy's @v/list). Pre-release
// and pseudo-versions are not listed by the proxy, which is fine: expansion
// presumes from tagged releases, and a module required at a pseudo-version keeps
// that observed pin.
func (c *Client) Versions(ctx context.Context, module string) ([]string, error) {
	raw, ok, err := c.get(ctx, escapeModule(module)+"/@v/list", "list|"+module)
	if err != nil || !ok {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			out = append(out, v)
		}
	}
	return out, nil
}

// ModFile returns the raw go.mod text for a module version. The caller parses
// its require block (kept in the gomod package so proxy has no dependency on the
// adapter's parser).
func (c *Client) ModFile(ctx context.Context, module, version string) ([]byte, bool, error) {
	return c.get(ctx, escapeModule(module)+"/@v/"+escapeVersion(version)+".mod", "mod|"+module+"@"+version)
}

// outcome tags how a single fetch resolved, so Stats accounting can be applied
// serially by the caller instead of mutated from inside a fetch (see fetch).
type outcome int

const (
	outReqErr    outcome = iota // request could not even be built — no category, Queried only
	outFromCache                // served from a fresh (or offline) cache entry
	outFromNet                  // fetched over the network; raw should be cached
	outNotFound                 // proxy has no record (404/410)
	outGap                      // lookup failed (offline miss, transport, bad status, read)
)

// fetchResult carries everything record needs to fold one fetch into Stats and
// the cache. It is a pure value — fetch mutates no shared Client state, so many
// fetchResults can be produced concurrently and recorded afterward.
type fetchResult struct {
	raw []byte
	ok  bool
	out outcome
	err error
	key string    // cache key to write on outFromNet
	now time.Time // fetch time to stamp the cache entry
}

// fetch performs the cache lookup and, on a miss, one HTTP GET. It reads the
// on-disk cache and the network but mutates NO shared Client state (neither
// Stats nor an in-memory cache), so it is safe to call from concurrent
// goroutines; the caller folds the result into Stats via record under its own
// serialization (Histories records after wg.Wait; get records inline).
func (c *Client) fetch(ctx context.Context, urlPath, cacheKey string) fetchResult {
	fullKey := "goproxy|" + cacheKey
	if raw, fresh, ok := c.Cache.GetRaw(fullKey); ok && (fresh || c.Offline) {
		return fetchResult{raw: raw, ok: true, out: outFromCache}
	}
	if c.Offline {
		return fetchResult{out: outGap}
	}
	u := "https://proxy.golang.org/" + urlPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fetchResult{out: outReqErr, err: err}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fetchResult{out: outGap, err: fmt.Errorf("go-proxy: %s: %w", urlPath, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return fetchResult{out: outNotFound}
	}
	if resp.StatusCode != http.StatusOK {
		return fetchResult{out: outGap, err: fmt.Errorf("go-proxy: %s: status %d", urlPath, resp.StatusCode)}
	}
	// Read ONE byte past the cap so an oversize body is detectable. Both
	// consumers of this function parse line-oriented text — @v/list is
	// newline-separated versions, .mod is go.mod source — not JSON, so a
	// silently truncated read does not fail to parse the way a cut-off JSON
	// document would. It yields a SHORTER list, or a go.mod missing requires,
	// with no error: the caller cannot tell a complete answer from a partial
	// one. Worse, the cut lands mid-line, so the final entry is a fragment
	// ("v1.708309.") that never existed — truncation manufacturing a version
	// rather than merely dropping some (D-143). An oversize body is therefore
	// a gap, not a partial answer.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fetchResult{out: outGap, err: err}
	}
	if len(raw) > maxResponseSize {
		return fetchResult{out: outGap, err: fmt.Errorf(
			"go-proxy: %s: response exceeds %d byte limit; refusing a truncated read", urlPath, maxResponseSize)}
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	return fetchResult{raw: raw, ok: true, out: outFromNet, key: fullKey, now: now()}
}

// record folds one fetch outcome into Stats and, for a network hit, writes the
// raw document to the cache. It is NOT safe for concurrent use — callers
// serialize it (get is single-goroutine; Histories records after wg.Wait).
func (c *Client) record(r fetchResult) {
	c.Stats.Queried++
	switch r.out {
	case outFromCache:
		c.Stats.FromCache++
	case outFromNet:
		c.Stats.FromNet++
		_ = c.Cache.PutRaw(r.key, r.raw, r.now)
	case outNotFound:
		c.Stats.NotFound++
	case outGap:
		c.Stats.Gaps++
	case outReqErr:
		// request never issued: Queried counted, no category
	}
}

// get is the serial convenience wrapper: fetch then record. Concurrent callers
// (Histories) use fetch/record directly so the recording stays single-threaded.
func (c *Client) get(ctx context.Context, urlPath, cacheKey string) ([]byte, bool, error) {
	r := c.fetch(ctx, urlPath, cacheKey)
	c.record(r)
	return r.raw, r.ok, r.err
}

// escapeModule applies the Go module proxy's case-encoding: an uppercase letter
// is escaped as "!" followed by its lowercase form, so github.com/Azure/foo is
// requested as github.com/!azure/foo. Without this, any module with an
// uppercase letter in its path 404s.
func escapeModule(module string) string {
	var b strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeVersion applies the same case-encoding to a version (a +incompatible or
// pseudo-version is otherwise passed through).
func escapeVersion(v string) string { return escapeModule(v) }
