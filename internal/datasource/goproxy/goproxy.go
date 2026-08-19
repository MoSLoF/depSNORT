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

func (c *Client) get(ctx context.Context, urlPath, cacheKey string) ([]byte, bool, error) {
	c.Stats.Queried++
	if raw, fresh, ok := c.Cache.GetRaw("goproxy|" + cacheKey); ok && (fresh || c.Offline) {
		c.Stats.FromCache++
		return raw, true, nil
	}
	if c.Offline {
		c.Stats.Gaps++
		return nil, false, nil
	}
	u := "https://proxy.golang.org/" + urlPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.Stats.Gaps++
		return nil, false, fmt.Errorf("go-proxy: %s: %w", urlPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		c.Stats.NotFound++
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		c.Stats.Gaps++
		return nil, false, fmt.Errorf("go-proxy: %s: status %d", urlPath, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		c.Stats.Gaps++
		return nil, false, err
	}
	c.Stats.FromNet++
	now := c.Now
	if now == nil {
		now = time.Now
	}
	_ = c.Cache.PutRaw("goproxy|"+cacheKey, raw, now())
	return raw, true, nil
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
