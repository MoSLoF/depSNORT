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
	got, err := c.CVEAliases(context.Background(), []datasource.Coord{
		{Ecosystem: "pypi", Name: "aiohttp", Version: "3.9.0"},
		{Ecosystem: "pypi", Name: "aiohttp", Version: "3.9.0"}, // dup -> one call
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.calls != 1 {
		t.Errorf("duplicate coord should be queried once, got %d calls", d.calls)
	}
	if len(got["GHSA-2fqr-mr3j-6wp8"]) != 1 || got["GHSA-2fqr-mr3j-6wp8"][0] != "CVE-2026-54279" {
		t.Errorf("GHSA->CVE mapping wrong: %v", got["GHSA-2fqr-mr3j-6wp8"])
	}
	if got["GO-2026-0001"][0] != "CVE-2026-11111" {
		t.Errorf("GO->CVE mapping wrong: %v", got["GO-2026-0001"])
	}
	if _, present := got["GHSA-noalias"]; present {
		t.Errorf("advisory with no CVE alias must be absent, got %v", got["GHSA-noalias"])
	}
}

func TestCVEAliasesOfflineIsSilentGap(t *testing.T) {
	c := &Client{HTTP: &aliasDoer{}, Endpoint: "https://example", Offline: true}
	got, err := c.CVEAliases(context.Background(), []datasource.Coord{{Ecosystem: "pypi", Name: "x", Version: "1"}})
	if err != nil || len(got) != 0 {
		t.Errorf("offline cold cache: want empty, no error; got %v %v", got, err)
	}
}
