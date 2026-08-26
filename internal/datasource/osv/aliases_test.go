package osv

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
)

type aliasDoer struct{ calls int }

func (d *aliasDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	body := `{"vulns":[
	  {"id":"GHSA-2fqr-mr3j-6wp8","aliases":["CVE-2026-54279","PYSEC-2026-2112"]},
	  {"id":"GO-2026-0001","aliases":["CVE-2026-11111"]},
	  {"id":"GHSA-noalias","aliases":["OSV-1"]}
	]}`
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestCVEAliasesResolvesAndFiltersToCVE(t *testing.T) {
	d := &aliasDoer{}
	c := &Client{HTTP: d, Endpoint: "https://example", Offline: false}
	got, err := c.HydrateAdvisories(context.Background(), []datasource.Coord{
		{Ecosystem: "pypi", Name: "aiohttp", Version: "3.9.0"},
		{Ecosystem: "pypi", Name: "aiohttp", Version: "3.9.0"}, // dup -> one call
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.calls != 1 {
		t.Errorf("duplicate coord should be queried once, got %d calls", d.calls)
	}
	if cs := got["GHSA-2fqr-mr3j-6wp8"].CVEs; len(cs) != 1 || cs[0] != "CVE-2026-54279" {
		t.Errorf("GHSA->CVE mapping wrong: %v", cs)
	}
	if cs := got["GO-2026-0001"].CVEs; len(cs) != 1 || cs[0] != "CVE-2026-11111" {
		t.Errorf("GO->CVE mapping wrong: %v", cs)
	}
	// An advisory whose only alias is a non-CVE cross-reference, and which
	// published no severity either, carries nothing this hydration can use.
	if _, present := got["GHSA-noalias"]; present {
		t.Errorf("advisory with nothing to hydrate must be absent, got %v", got["GHSA-noalias"])
	}
}

func TestCVEAliasesOfflineIsSilentGap(t *testing.T) {
	c := &Client{HTTP: &aliasDoer{}, Endpoint: "https://example", Offline: true}
	got, err := c.HydrateAdvisories(context.Background(), []datasource.Coord{{Ecosystem: "pypi", Name: "x", Version: "1"}})
	if err != nil || len(got) != 0 {
		t.Errorf("offline cold cache: want empty, no error; got %v %v", got, err)
	}
}

// D-147: /v1/query carries severity as a CVSS VECTOR plus, for GHSA records, a
// qualitative label. querybatch returns neither, so this is the only place the
// tool can learn how bad an advisory is.
type sevDoer struct{}

func (sevDoer) Do(*http.Request) (*http.Response, error) {
	body := `{"vulns":[
	  {"id":"GHSA-scored","aliases":["CVE-2026-1"],
	   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	   "database_specific":{"severity":"CRITICAL"}},
	  {"id":"GHSA-label-only","aliases":[],
	   "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}],
	   "database_specific":{"severity":"HIGH"}},
	  {"id":"GHSA-picks-max",
	   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
	               {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}
	]}`
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestD147HydrationCarriesSeverity(t *testing.T) {
	c := &Client{HTTP: sevDoer{}, Endpoint: "https://example"}
	got, err := c.HydrateAdvisories(context.Background(), []datasource.Coord{
		{Ecosystem: "npm", Name: "x", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if h := got["GHSA-scored"]; !h.Scored || h.Severity != 9.8 || h.Label != "CRITICAL" {
		t.Errorf("scored vector should yield 9.8/CRITICAL, got %+v", h)
	}
	// A v4 vector is not scorable here, so the label is the only signal — and it
	// must survive rather than the record reading as unrated.
	if h := got["GHSA-label-only"]; h.Scored {
		t.Errorf("a CVSS v4 vector must not be scored, got %+v", h)
	} else if h.Label != "HIGH" {
		t.Errorf("label must survive an unscorable vector, got %+v", h)
	}
	// Several scorable vectors: take the worst, never whichever came first.
	if h := got["GHSA-picks-max"]; !h.Scored || h.Severity != 7.5 {
		t.Errorf("expected the higher of 5.3 and 7.5, got %+v", h)
	}
}
