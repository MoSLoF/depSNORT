package builtin

import (
	"encoding/json"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// D-146: OSV's querybatch returns advisory ids with no aliases, so a
// GHSA-primary advisory arrives carrying no CVE identity. D-145 leaned on that
// identity twice over — advisoryWhen reads a CVE year when no timestamp exists,
// and EPSS is CVE-keyed — and the report never showed it at all. The tool could
// resolve GHSA-x to CVE-2026-9002, rank on it, and still print only the GHSA, so
// an operator searching for the CVE they had been briefed on found nothing.

func d146Run(t *testing.T, advs []datasource.Advisory) (string, []string, []string) {
	t.Helper()
	id := "pkg:npm/widget@1.0.0"
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	fs := (KnownVuln{}).Run(&check.Context{
		Graph: g, Advisories: map[string][]datasource.Advisory{id: advs},
	})
	if len(fs) != 1 {
		t.Fatalf("want one aggregated finding, got %d", len(fs))
	}
	return fs[0].Title, fs[0].Advisories, fs[0].Aliases
}

// TestD146AliasIdentityReachesTheReport is the gap itself.
func TestD146AliasIdentityReachesTheReport(t *testing.T) {
	advs := []datasource.Advisory{
		{ID: "GHSA-aaaa-bbbb-cccc", Source: "osv", Aliases: []string{"CVE-2026-9002"}},
		{ID: "CVE-2020-1", Source: "osv"},
	}
	_, ids, aliases := d146Run(t, advs)
	if strings.Join(aliases, ",") != "CVE-2026-9002" {
		t.Errorf("the CVE behind the GHSA must reach the finding, got %v", aliases)
	}
	// And it must be findable in the serialized report, which is where an
	// operator actually searches.
	f := struct {
		Advisories []string `json:"advisories"`
		Aliases    []string `json:"advisory_aliases"`
	}{ids, aliases}
	raw, _ := json.Marshal(f)
	if !strings.Contains(string(raw), "CVE-2026-9002") {
		t.Errorf("alias unrecoverable from the emitted finding: %s", raw)
	}
}

// TestD146AliasesDoNotInflateTheCount is the boundary that protects D-144's
// contract: Advisories means "the advisories this finding aggregates" and must
// keep matching the count in the title. An alias is another name for one of
// them, not an additional vulnerability.
func TestD146AliasesDoNotInflateTheCount(t *testing.T) {
	advs := []datasource.Advisory{
		{ID: "GHSA-aaaa-bbbb-cccc", Source: "osv", Aliases: []string{"CVE-2026-9002"}},
		{ID: "GHSA-dddd-eeee-ffff", Source: "osv", Aliases: []string{"CVE-2026-9003"}},
	}
	title, ids, aliases := d146Run(t, advs)
	if !strings.Contains(title, "2 known vulnerabilities") {
		t.Errorf("two advisories with two aliases is still two vulnerabilities: %q", title)
	}
	if len(ids) != 2 {
		t.Errorf("Advisories should hold the 2 advisory ids, got %v", ids)
	}
	if len(aliases) != 2 {
		t.Errorf("Aliases should hold the 2 CVE identities, got %v", aliases)
	}
}

// TestD146AliasThatRepeatsAPrimaryIDIsNotListedTwice: OSV can return a CVE both
// as an advisory in its own right and as another advisory's alias. Listing it
// in both places would read as two separate identities.
func TestD146AliasThatRepeatsAPrimaryIDIsNotListedTwice(t *testing.T) {
	advs := []datasource.Advisory{
		{ID: "GHSA-aaaa-bbbb-cccc", Source: "osv", Aliases: []string{"CVE-2020-1"}},
		{ID: "CVE-2020-1", Source: "osv"},
	}
	_, ids, aliases := d146Run(t, advs)
	if len(aliases) != 0 {
		t.Errorf("CVE-2020-1 is already an advisory id (%v); it is not also an alias: %v", ids, aliases)
	}
}

// TestD146NoAliasesIsNoField: the overwhelmingly common shape is CVE-primary
// advisories with nothing to hydrate, and those must carry no alias noise.
func TestD146NoAliasesIsNoField(t *testing.T) {
	_, _, aliases := d146Run(t, []datasource.Advisory{
		{ID: "CVE-2020-1", Source: "osv"}, {ID: "CVE-2020-2", Source: "osv"},
	})
	if len(aliases) != 0 {
		t.Errorf("expected no aliases, got %v", aliases)
	}
}

// TestD146AliasesAreSortedAndDeduped keeps the output diffable in a CI gate
// (D-09) when two advisories alias the same CVE.
func TestD146AliasesAreSortedAndDeduped(t *testing.T) {
	advs := []datasource.Advisory{
		{ID: "GHSA-zzzz", Source: "osv", Aliases: []string{"CVE-2026-9002", "CVE-2020-5"}},
		{ID: "GHSA-aaaa", Source: "osv", Aliases: []string{"CVE-2026-9002"}},
	}
	_, _, aliases := d146Run(t, advs)
	if strings.Join(aliases, ",") != "CVE-2020-5,CVE-2026-9002" {
		t.Errorf("aliases should be sorted and deduped, got %v", aliases)
	}
}
