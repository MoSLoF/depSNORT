// Package npmreg reads publish-time metadata from the npm registry: the
// per-package "packument" whose `time` map gives every version's publish
// timestamp. That timeline is what the temporal axis (VC-004/VC-005) reasons
// over — a lockfile pins one version and knows nothing about release history.
//
// Only registry METADATA is fetched — never a package tarball, never an install
// (Decision D-04). Responses are cached on disk and an offline mode serves the
// cache exclusively, so temporal gating stays deterministic and air-gappable.
package npmreg

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
	"ihbv.io/depsnort/internal/installsurface"
)

// DefaultEndpoint is the public npm registry.
const DefaultEndpoint = "https://registry.npmjs.org"

// registryConcurrency bounds simultaneous packument fetches. Enough to hide
// per-request latency on a large tree, low enough to stay a polite client.
const registryConcurrency = 8

// ErrNotFound reports that the registry has no record of a package (HTTP 404).
// This is an ordinary condition — private packages, internal scopes, and
// unpublished names all produce it — so callers count it rather than treating
// the scan as degraded.
var ErrNotFound = errors.New("package not found on registry")

// Doer is the minimal HTTP surface; injectable so tests never touch a network.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client fetches packuments.
type Client struct {
	HTTP     Doer
	Cache    *datasource.Cache
	Endpoint string
	Offline  bool
	Now      func() time.Time

	Stats datasource.Stats
}

// New returns a Client with sensible defaults.
func New(cache *datasource.Cache, offline bool) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Cache:    cache,
		Endpoint: DefaultEndpoint,
		Offline:  offline,
		Now:      time.Now,
	}
}

// Name identifies the source.
func (*Client) Name() string { return "npm-registry" }

// Ecosystem returns the ecosystem string this source covers.
func (*Client) Ecosystem() string { return "npm" }

// GetStats returns the stats from the last Histories call.
func (c *Client) GetStats() datasource.Stats { return c.Stats }

// packument is the subset of the registry document we keep. The full document
// is large; everything not named here is discarded at decode time.
type packument struct {
	Name        string            `json:"name"`
	Time        map[string]string `json:"time"`
	Maintainers []maintainer      `json:"maintainers"`
	// Versions is the per-version manifest map. Two facts are taken from it and
	// everything else is discarded at decode time:
	//
	//   _npmUser — the account that published THAT version. The package-level
	//   Maintainers list above cannot answer this, and it reads identically
	//   before and after a stolen token pushes a release (D-40).
	//
	//   scripts — the version's declared lifecycle hooks. This is the only
	//   drift signal available with no baseline file and no artifact download:
	//   the packument is one request this scan already makes and already
	//   caches, and it states outright that 1.6.3 declares a postinstall that
	//   1.6.2 did not.
	Versions map[string]packumentVersion `json:"versions"`
}

type packumentVersion struct {
	NpmUser maintainer        `json:"_npmUser"`
	Scripts map[string]string `json:"scripts"`
}

type maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// cacheKey is the packument cache key for a package name.
func cacheKey(name string) string { return "npm|" + name + "|packument" }

// escapePath encodes a package name for a registry URL, keeping the scope
// separator readable (npm accepts @scope%2Fname; it also accepts @scope/name).
func escapePath(name string) string {
	if strings.HasPrefix(name, "@") {
		if i := strings.IndexByte(name, '/'); i > 0 {
			return url.PathEscape(name[:i]) + "%2F" + url.PathEscape(name[i+1:])
		}
	}
	return url.PathEscape(name)
}

// Histories fetches release history for each unique package name. Results are
// keyed by package name. Packages that cannot be fetched are omitted and
// counted as gaps rather than silently treated as clean.
func (c *Client) Histories(ctx context.Context, names []string) (map[string]*datasource.ReleaseHistory, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out := make(map[string]*datasource.ReleaseHistory, len(names))
	c.Stats = datasource.Stats{Queried: len(names), Offline: c.Offline}

	// Cache pass first, serially: it is local and cheap, and resolving it up
	// front means only genuine misses cost a round trip.
	var misses []string
	for _, name := range names {
		if raw, fresh, ok := c.Cache.GetRaw(cacheKey(name)); ok && (fresh || c.Offline) {
			if h, err := parsePackument(name, raw); err == nil {
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

	// Network pass, bounded-parallel. Packuments are large and one GET per
	// package name adds up fast: a 400-dependency tree fetched serially is 400
	// round trips of multi-megabyte documents, which reads as a hang. Errors are
	// collected per name and the reported one is chosen by sorted name, so a
	// degraded run still produces a deterministic message (Decision D-13).
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
		sem     = make(chan struct{}, registryConcurrency)
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
			h, err := parsePackument(name, raw)
			results[i] = result{name: name, h: h, raw: raw, err: err}
		}(i, name)
	}
	wg.Wait()

	// Fold results in input order so stats and cache writes stay deterministic.
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
		_ = c.Cache.PutRaw(cacheKey(r.name), r.raw, now())
	}
	if len(errsBy) > 0 {
		names := make([]string, 0, len(errsBy))
		for n := range errsBy {
			names = append(names, n)
		}
		sort.Strings(names)
		return out, errsBy[names[0]]
	}
	return out, nil
}

// fetch retrieves the raw packument JSON for a package.
func (c *Client) fetch(ctx context.Context, name string) ([]byte, error) {
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/"+escapePath(name), nil)
	if err != nil {
		return nil, err
	}
	// The abbreviated packument omits the `time` map, so the full document is
	// required here. It is large; the disk cache is what keeps this cheap.
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npmreg: %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("npmreg: %s: %w", name, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("npmreg: %s: status %d: %s", name, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	// Cap individual packument reads at 100 MB. Even the largest npm packages
	// (socket.io, lodash) are well under this, and the bound prevents a
	// compromised or misbehaving registry from exhausting process memory.
	const maxPackumentSize = 100 * 1024 * 1024
	return io.ReadAll(io.LimitReader(resp.Body, maxPackumentSize))
}

// parsePackument turns a raw packument into a ReleaseHistory.
func parsePackument(name string, raw []byte) (*datasource.ReleaseHistory, error) {
	var p packument
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("npmreg: parsing packument for %s: %w", name, err)
	}
	h := &datasource.ReleaseHistory{Package: name, Ecosystem: "npm"}
	for version, ts := range p.Time {
		// "created" and "modified" are not versions.
		if version == "created" || version == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		h.Releases = append(h.Releases, datasource.Release{Version: version, Published: t})
	}
	h.Sort()
	for _, m := range p.Maintainers {
		h.Maintainers = append(h.Maintainers, m.Name)
	}

	for version, v := range p.Versions {
		if v.NpmUser.Name != "" {
			if h.Publishers == nil {
				h.Publishers = map[string]datasource.Publisher{}
			}
			// npm exposes no stable numeric account ID on _npmUser, so the
			// login IS the identity here. Recorded in both fields rather than
			// left half-empty so Key() behaves the same across ecosystems.
			h.Publishers[version] = datasource.Publisher{
				ID:     v.NpmUser.Name,
				Name:   v.NpmUser.Name,
				Email:  v.NpmUser.Email,
				Source: "npm._npmUser",
			}
		}
		if hooks := installHooksOf(v.Scripts); len(hooks) > 0 {
			if h.Hooks == nil {
				h.Hooks = map[string][]string{}
			}
			h.Hooks[version] = hooks
		}
	}
	return h, nil
}

// installHooksOf returns the install-time lifecycle hooks a version's scripts
// block declares, sorted.
//
// Only install-time names count: a `test` or `build` script is not something
// `npm install` fires, and treating every scripts entry as a hook would make
// the drift signal fire on essentially every release of every package.
func installHooksOf(scripts map[string]string) []string {
	if len(scripts) == 0 {
		return nil
	}
	var out []string
	for name, body := range scripts {
		if strings.TrimSpace(body) == "" {
			continue
		}
		if installsurface.IsInstallHook(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
