// Package osv is the OSV.dev advisory Source. It queries the batched endpoint
// (POST /v1/querybatch), classifies malicious-package advisories (MAL-*), and
// layers an on-disk cache with an offline mode so a scan can run air-gapped.
//
// Only package metadata crosses the wire — never a package payload, never an
// install. This is consistent with the zero-execution ethos (Decision D-04).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// DefaultEndpoint is the OSV.dev API base.
const DefaultEndpoint = "https://api.osv.dev"

// maxBatch is OSV's querybatch cap.
const maxBatch = 1000

// Doer is the minimal HTTP surface (http.Client satisfies it). Injectable so
// tests run without a network.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is an OSV advisory Source.
type Client struct {
	HTTP     Doer
	Cache    *datasource.Cache
	Endpoint string
	Offline  bool
	// Now is injected for deterministic cache timestamps; defaults to time.Now.
	Now func() time.Time
	// Bundled is the last-tier fallback lookup, consulted only when neither
	// the cache nor a live query has an answer for a coordinate. Defaults to
	// BundledLookup (the dataset compiled into this binary); set to nil to
	// disable the fallback entirely (-no-osv-bundled).
	Bundled func(key string) (adv []datasource.Advisory, generatedAt time.Time, ok bool)

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
		Bundled:  BundledLookup,
	}
}

// Name implements datasource.Source.
func (*Client) Name() string { return "osv" }

// ecosystemName maps our internal ecosystem id to OSV's spelling. OSV uses
// specific casing and naming for each ecosystem; passing our internal id
// as-is would silently return zero advisories.
func ecosystemName(eco string) string {
	switch eco {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "gem":
		return "RubyGems"
	case "cargo":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "nuget":
		return "NuGet"
	case "gomod":
		return "Go"
	case "maven":
		// Maven coordinates regardless of manifest family: the clojure
		// adapter's project.clj / deps.edn nodes resolve here (D-162). Node
		// names are already "group:artifact", OSV's Maven package spelling.
		return "Maven"
	default:
		return eco
	}
}

// ---- OSV wire types ----
type qbReq struct {
	Queries []qbQuery `json:"queries"`
}
type qbQuery struct {
	Package qbPkg  `json:"package"`
	Version string `json:"version"`
}
type qbPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type qbResp struct {
	Results []qbResult `json:"results"`
}
type qbResult struct {
	Vulns []qbVuln `json:"vulns"`
}
type qbVuln struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// QueryBatch implements datasource.Source. Tiered resolution per coordinate:
//
//  1. On-disk cache — fresh, or any entry when offline.
//  2. Live network query — skipped entirely when offline.
//  3. The compiled-in bundled fallback dataset — consulted only when neither
//     of the above had an answer (an offline cache miss, or a live query
//     that failed outright). Never mistaken for a live check: every use is
//     recorded on c.Stats with the dataset's own generation time.
//  4. A typed gap — nothing above had this coordinate.
//
// It updates c.Stats.
func (c *Client) QueryBatch(ctx context.Context, coords []datasource.Coord) ([][]datasource.Advisory, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out := make([][]datasource.Advisory, len(coords))
	c.Stats = datasource.Stats{Queried: len(coords), Offline: c.Offline}

	var missIdx []int
	for i, co := range coords {
		if adv, fresh, ok := c.Cache.Get(co.Key()); ok && (fresh || c.Offline) {
			out[i] = adv
			c.Stats.FromCache++
			c.tally(adv)
			continue
		}
		if c.Offline {
			c.resolveFromBundledOrGap(out, i, co)
			continue
		}
		missIdx = append(missIdx, i)
	}

	// Network fetch for misses, in chunks.
	for start := 0; start < len(missIdx); start += maxBatch {
		end := start + maxBatch
		if end > len(missIdx) {
			end = len(missIdx)
		}
		chunk := missIdx[start:end]
		results, err := c.postBatch(ctx, coords, chunk)
		if err != nil {
			// The live query failed for this chunk and everything queued
			// after it. Before giving up, check the bundled fallback for
			// each coordinate — real (if not live-fresh) coverage beats a
			// silent gap, the same reasoning that makes -osv-snapshot worth
			// having (Decision D-09 extended to data shipped with the binary
			// itself rather than imported by hand).
			for _, i := range missIdx[start:] {
				c.resolveFromBundledOrGap(out, i, coords[i])
			}
			return out, err
		}
		for j, i := range chunk {
			adv := results[j]
			out[i] = adv
			c.Stats.FromNet++
			c.tally(adv)
			_ = c.Cache.Put(coords[i].Key(), adv, now())
		}
	}
	return out, nil
}

// resolveFromBundledOrGap serves coord from the compiled-in fallback dataset
// when available, otherwise records a gap. A bundled hit is deliberately NOT
// written into the on-disk cache: doing so would stamp it with "now" and make
// a build-time dataset indistinguishable from a fresh live check on the very
// next run.
//
// A hit only counts as COVERAGE when the entry carries malicious-package
// intelligence (finding DS-REV-01). The tier is documented, and reported, as
// the offline substitute for a live VC-001 check; an entry holding nothing but
// ordinary CVEs cannot answer the question that tier exists to answer, however
// many advisories it contains. Before this, any hit incremented FromBundled and
// suppressed the gap, so a coordinate present with GHSA records alone returned
// exit 0 — a clean bill of health from a dataset that had never looked for
// malware.
//
// The advisories are still returned either way: VC-008 context is real and
// there is no reason to discard it. What changes is the accounting — the
// coordinate is ALSO recorded as a gap, so it reaches
// Coverage.Incomplete() and can fail a run under -fail-on-incomplete, which is
// the honest answer to "was this checked for malicious packages?".
func (c *Client) resolveFromBundledOrGap(out [][]datasource.Advisory, i int, coord datasource.Coord) {
	if c.Bundled != nil {
		if adv, generatedAt, ok := c.Bundled(coord.Key()); ok {
			out[i] = adv
			c.tally(adv)
			at := generatedAt
			c.Stats.BundledDatasetAt = &at
			if hasMalicious(adv) {
				c.Stats.FromBundled++
				return
			}
			// Present, but not as malicious-package coverage.
			c.Stats.BundledNonMalicious++
			c.Stats.Gaps++
			return
		}
	}
	out[i] = nil
	c.Stats.Gaps++
}

// hasMalicious reports whether a bundled entry carries at least one
// malicious-package advisory. Reads the Malicious flag the snapshot format
// already carries, falling back to the ID classifier so a hand-authored or
// older snapshot whose flag was never set is judged on the same rule the live
// path uses (datasource.ClassifyMalicious).
func hasMalicious(adv []datasource.Advisory) bool {
	for _, a := range adv {
		if a.Malicious || datasource.ClassifyMalicious(a.ID) {
			return true
		}
	}
	return false
}

func (c *Client) tally(adv []datasource.Advisory) {
	c.Stats.Advisories += len(adv)
	for _, a := range adv {
		if a.Malicious {
			c.Stats.Malicious++
		}
	}
}

// postBatch queries OSV for the coords at the given indices and returns
// advisories aligned to that index slice.
func (c *Client) postBatch(ctx context.Context, coords []datasource.Coord, idx []int) ([][]datasource.Advisory, error) {
	body := qbReq{Queries: make([]qbQuery, len(idx))}
	for k, i := range idx {
		co := coords[i]
		body.Queries[k] = qbQuery{
			Package: qbPkg{Name: co.Name, Ecosystem: ecosystemName(co.Ecosystem)},
			Version: co.Version,
		}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/querybatch", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: querybatch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("osv: querybatch status %d: %s", resp.StatusCode, string(snippet))
	}
	var parsed qbResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("osv: decoding querybatch: %w", err)
	}
	if len(parsed.Results) != len(idx) {
		return nil, fmt.Errorf("osv: expected %d results, got %d", len(idx), len(parsed.Results))
	}

	out := make([][]datasource.Advisory, len(idx))
	for k, r := range parsed.Results {
		adv := make([]datasource.Advisory, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			a := datasource.Advisory{
				ID:        v.ID,
				Malicious: datasource.ClassifyMalicious(v.ID),
				Source:    "osv",
			}
			if t, err := time.Parse(time.RFC3339, v.Modified); err == nil {
				a.Modified = t
			}
			adv = append(adv, a)
		}
		out[k] = adv
	}
	return out, nil
}
