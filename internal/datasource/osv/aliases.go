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

// Hydration is what /v1/query knows about one advisory beyond its id.
type Hydration struct {
	// CVEs are the advisory's CVE aliases (CVE-only; PYSEC/GHSA cross-references
	// are dropped because nothing downstream keys on them).
	CVEs []string
	// Severity is the CVSS v3.x base score, valid only when Scored is true.
	Severity float64
	Scored   bool
	// Label is the database's qualitative rating, for records whose vector this
	// tool does not score (v2, v4) or which published no vector at all.
	Label string
}

// HydrateAdvisories fills in what OSV's /v1/querybatch leaves out.
//
// depSNORT's primary path uses querybatch, which returns only advisory IDs and
// `modified` — no aliases and no severity. So a GHSA-primary advisory arrives
// with no CVE identity (EPSS is CVE-keyed and cannot score it) and no severity
// at all. This fills both gaps from the fuller /v1/query endpoint, one call per
// coordinate, cached. Offline: cache only; a miss is a silent gap.
//
// The result maps advisory ID -> what was learned about it.
func (c *Client) HydrateAdvisories(ctx context.Context, coords []datasource.Coord) (map[string]Hydration, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out := map[string]Hydration{}
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
		mergeHydration(out, raw)
	}
	return out, firstErr
}

type queryAliasResp struct {
	Vulns []struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"` // a CVSS VECTOR string, not a number
		} `json:"severity"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"vulns"`
}

func mergeHydration(out map[string]Hydration, raw []byte) {
	var r queryAliasResp
	if json.Unmarshal(raw, &r) != nil {
		return
	}
	for _, v := range r.Vulns {
		h := Hydration{Label: strings.ToUpper(strings.TrimSpace(v.DatabaseSpecific.Severity))}
		for _, a := range v.Aliases {
			if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
				h.CVEs = append(h.CVEs, strings.ToUpper(a))
			}
		}
		// Highest scorable vector wins. A record can carry several (a v3 and a
		// v4, say); taking the max of the ones we CAN score is safer than
		// trusting position, and never invents a score for one we cannot.
		for _, sv := range v.Severity {
			if score, ok := BaseScore(sv.Score); ok && (!h.Scored || score > h.Severity) {
				h.Severity, h.Scored = score, true
			}
		}
		if len(h.CVEs) > 0 || h.Scored || h.Label != "" {
			out[v.ID] = h
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
