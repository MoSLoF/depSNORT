package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ihbv.io/depsnort/internal/datasource"
)

// CVEAliases resolves each coordinate's advisories to their CVE aliases.
//
// depSNORT's primary path uses OSV's /v1/querybatch, which returns only advisory
// IDs (GHSA-…, GO-…) and NO aliases — so a GHSA-primary advisory carries no CVE,
// and EPSS (which is CVE-keyed) cannot score it. This fills that gap with the
// fuller /v1/query endpoint (one call per coordinate, cached), which returns each
// advisory's aliases. It is used only for EPSS enrichment and leaves the core
// querybatch path untouched. Offline: cache only; a miss is a silent gap.
//
// The result maps advisory ID -> its CVE aliases (CVE-only; other aliases such as
// PYSEC/GHSA are dropped since EPSS cannot use them).
func (c *Client) CVEAliases(ctx context.Context, coords []datasource.Coord) (map[string][]string, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out := map[string][]string{}
	var firstErr error
	seen := map[string]bool{}
	for _, co := range coords {
		if co.Name == "" || co.Version == "" {
			continue
		}
		key := "osvq_" + co.Key()
		if seen[key] {
			continue
		}
		seen[key] = true

		var raw []byte
		if c.Cache != nil {
			if b, fresh, ok := c.Cache.GetRaw(key); ok && (fresh || c.Offline) {
				raw = b
			}
		}
		if raw == nil {
			if c.Offline {
				continue // cache-only offline; miss is a silent gap
			}
			b, err := c.queryOne(ctx, co)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			raw = b
			if c.Cache != nil {
				_ = c.Cache.PutRaw(key, raw, now())
			}
		}
		mergeAliases(out, raw)
	}
	return out, firstErr
}

type queryAliasResp struct {
	Vulns []struct {
		ID      string   `json:"id"`
		Aliases []string `json:"aliases"`
	} `json:"vulns"`
}

func mergeAliases(out map[string][]string, raw []byte) {
	var r queryAliasResp
	if json.Unmarshal(raw, &r) != nil {
		return
	}
	for _, v := range r.Vulns {
		var cves []string
		for _, a := range v.Aliases {
			if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
				cves = append(cves, strings.ToUpper(a))
			}
		}
		if len(cves) > 0 {
			out[v.ID] = cves
		}
	}
}

func (c *Client) queryOne(ctx context.Context, co datasource.Coord) ([]byte, error) {
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	body, _ := json.Marshal(qbQuery{
		Package: qbPkg{Ecosystem: ecosystemName(co.Ecosystem), Name: co.Name},
		Version: co.Version,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv query: unexpected status %d", resp.StatusCode)
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
