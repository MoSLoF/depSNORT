// Package epss enriches disclosed vulnerabilities with EPSS scores — the FIRST.org
// Exploit Prediction Scoring System probability (0..1) that a CVE will be
// exploited in the wild in the next 30 days, plus its percentile rank. It turns a
// flat VC-008 list ("96 vulnerable packages") into a prioritized one ("these 4
// have EPSS > 0.5"). EPSS is keyed on CVE, so callers resolve advisory IDs
// (GHSA/GO/PYSEC) to their CVE aliases before querying.
//
// Like the other data sources it is read-only (D-04), stdlib-only (D-10), cached,
// and offline-aware: offline it serves cached scores and discloses the rest as
// gaps rather than inventing a score.
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// DefaultEndpoint is the FIRST.org EPSS API. It accepts a comma-separated cve
// list and returns one row per CVE that has a score (unknown CVEs are simply
// absent — not an error).
const DefaultEndpoint = "https://api.first.org/data/v1/epss"

// maxBatch is the API's default page limit; requesting at most this many CVEs per
// call keeps every response to a single page (total <= requested <= limit).
const maxBatch = 100

// Doer is the subset of *http.Client used here (injected for tests).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Score is a CVE's EPSS result.
type Score struct {
	EPSS       float64 `json:"epss"`       // probability of exploitation in the wild (0..1)
	Percentile float64 `json:"percentile"` // rank among all scored CVEs (0..1)
	Date       string  `json:"date"`       // model date the score is from
}

// Client fetches EPSS scores, tiered cache -> live -> gap, mirroring the OSV
// client's shape.
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
		HTTP:     &http.Client{Timeout: 20 * time.Second},
		Cache:    cache,
		Endpoint: DefaultEndpoint,
		Offline:  offline,
		Now:      time.Now,
	}
}

// Name implements datasource.Source-style identification.
func (*Client) Name() string { return "epss" }

// wire types for the FIRST.org response envelope.
type epssResp struct {
	Status string    `json:"status"`
	Total  int       `json:"total"`
	Data   []epssRow `json:"data"`
}

type epssRow struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"` // returned as strings, e.g. "0.999990000"
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// Scores returns EPSS scores for the given CVE IDs. Input is normalized and
// de-duplicated; non-CVE IDs are ignored (EPSS only scores CVEs). A CVE with no
// published score is simply absent from the result (counted as a gap, not an
// error). It updates c.Stats.
func (c *Client) Scores(ctx context.Context, cves []string) (map[string]Score, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	want := normalizeCVEs(cves)
	c.Stats = datasource.Stats{Queried: len(want), Offline: c.Offline}
	out := make(map[string]Score, len(want))

	// Tier 1: cache. Offline uses any cached entry; online only fresh ones.
	var missing []string
	for _, cve := range want {
		if c.Cache != nil {
			if raw, fresh, ok := c.Cache.GetRaw(cacheKey(cve)); ok && (fresh || c.Offline) {
				var s Score
				if json.Unmarshal(raw, &s) == nil {
					out[cve] = s
					c.Stats.FromCache++
					continue
				}
			}
		}
		missing = append(missing, cve)
	}

	if c.Offline {
		c.Stats.Gaps += len(missing)
		return out, nil
	}

	// Tier 2: live, in <=maxBatch chunks (one page each).
	var firstErr error
	for _, chunk := range chunkStrings(missing, maxBatch) {
		rows, err := c.fetch(ctx, chunk)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			c.Stats.Gaps += len(chunk) // the whole chunk is unresolved
			continue
		}
		got := map[string]bool{}
		for _, r := range rows {
			s, ok := r.toScore()
			if !ok {
				continue
			}
			cve := strings.ToUpper(r.CVE)
			out[cve] = s
			got[cve] = true
			c.Stats.FromNet++
			if c.Cache != nil {
				if b, mErr := json.Marshal(s); mErr == nil {
					_ = c.Cache.PutRaw(cacheKey(cve), b, now())
				}
			}
		}
		// CVEs in the chunk the API had no score for are gaps, not errors.
		for _, cve := range chunk {
			if !got[cve] {
				c.Stats.Gaps++
			}
		}
	}
	return out, firstErr
}

func (c *Client) fetch(ctx context.Context, cves []string) ([]epssRow, error) {
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	q := url.Values{}
	q.Set("cve", strings.Join(cves, ","))
	q.Set("limit", fmt.Sprintf("%d", maxBatch))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: unexpected status %d", resp.StatusCode)
	}
	var env epssResp
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("epss: decode: %w", err)
	}
	return env.Data, nil
}

func (r epssRow) toScore() (Score, bool) {
	e, err1 := parseFloat(r.EPSS)
	p, err2 := parseFloat(r.Percentile)
	if err1 != nil || err2 != nil {
		return Score{}, false
	}
	return Score{EPSS: e, Percentile: p, Date: r.Date}, true
}

func cacheKey(cve string) string { return "epss_" + strings.ToUpper(cve) }

// normalizeCVEs upper-cases, keeps only CVE-shaped IDs, and de-duplicates while
// preserving a deterministic (sorted) order.
func normalizeCVEs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range in {
		u := strings.ToUpper(strings.TrimSpace(id))
		if !strings.HasPrefix(u, "CVE-") {
			continue
		}
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func chunkStrings(in []string, size int) [][]string {
	if size <= 0 {
		size = 1
	}
	var out [][]string
	for i := 0; i < len(in); i += size {
		end := i + size
		if end > len(in) {
			end = len(in)
		}
		out = append(out, in[i:end])
	}
	return out
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%g", &f)
	return f, err
}
