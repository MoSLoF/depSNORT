package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// The live-run regression: axios@0.21.0 alone returned 25 advisories, which
// buried every supply-chain signal. One finding per package, not per advisory.
func TestVC008AggregatesPerPackage(t *testing.T) {
	id := "pkg:npm/axios@0.21.0"
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: "axios", Version: "0.21.0"})

	var advs []datasource.Advisory
	for _, s := range []string{
		"GHSA-3g43-6gmg-66jw", "GHSA-3p68-rc4w-qgx5", "GHSA-43fc-jf86-j433",
		"GHSA-4w2v-q235-vp99", "GHSA-5c9x-8gcm-mpgx", "GHSA-62hf-57xw-28j9",
		"GHSA-6chq-wfr3-2hj9", "GHSA-7q8q-rj6j-mhjq", "GHSA-898c-q2cr-xwhg",
		"GHSA-cph5-m8f7-6c5x", "GHSA-fvcv-3m26-pcqx", "CVE-2020-28168",
	} {
		advs = append(advs, datasource.Advisory{ID: s, Source: "osv"})
	}

	fs := (KnownVuln{}).Run(&check.Context{
		Graph:      g,
		Advisories: map[string][]datasource.Advisory{id: advs},
	})
	if len(fs) != 1 {
		t.Fatalf("VC-008 findings = %d, want exactly 1 aggregated finding", len(fs))
	}
	f := fs[0]
	if !strings.Contains(f.Title, "12 known vulnerabilities") {
		t.Errorf("title should carry the count: %q", f.Title)
	}
	// The listing cap must be disclosed, not silent.
	if !strings.Contains(f.Evidence, "+4 more") {
		t.Errorf("truncation not disclosed in evidence: %q", f.Evidence)
	}
}

func TestVC008SingularWording(t *testing.T) {
	id := "pkg:npm/minimist@1.2.5"
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: "minimist", Version: "1.2.5"})
	fs := (KnownVuln{}).Run(&check.Context{
		Graph:      g,
		Advisories: map[string][]datasource.Advisory{id: {{ID: "CVE-2021-44906"}}},
	})
	if len(fs) != 1 {
		t.Fatalf("findings = %d", len(fs))
	}
	if !strings.Contains(fs[0].Title, "1 known vulnerability") {
		t.Errorf("singular wording wrong: %q", fs[0].Title)
	}
}
