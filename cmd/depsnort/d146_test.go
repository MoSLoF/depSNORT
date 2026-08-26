package main

import (
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// D-146: hydration used to ride along inside the -epss block, so on a default
// scan Advisory.Aliases was empty always. Decoupling it means every scan can now
// spend requests here, and aliasCandidates is what stops that from being one per
// vulnerable package: only a NON-CVE advisory id can be hiding a CVE identity.

func d146Graph(t *testing.T, adv map[string][]datasource.Advisory) (*graph.Graph, *check.Context) {
	t.Helper()
	g := graph.New()
	for id := range adv {
		g.AddNode(&graph.Node{
			ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
			Name: id, Version: "1.0.0",
		})
	}
	return g, &check.Context{Graph: g, Advisories: adv}
}

func TestD146OnlyNonCVEAdvisoriesAreWorthQuerying(t *testing.T) {
	g, ctx := d146Graph(t, map[string][]datasource.Advisory{
		"cve-only":  {{ID: "CVE-2020-1"}, {ID: "CVE-2020-2"}},
		"has-ghsa":  {{ID: "CVE-2020-3"}, {ID: "GHSA-aaaa-bbbb-cccc"}},
		"ghsa-only": {{ID: "GHSA-dddd-eeee-ffff"}},
		"go-only":   {{ID: "GO-2024-1234"}},
	})
	got := map[string]bool{}
	for _, c := range aliasCandidates(g, ctx) {
		got[c.Name] = true
	}
	if got["cve-only"] {
		t.Error("a package whose advisories are all CVE-primary already carries its CVE identity; querying it learns nothing")
	}
	for _, want := range []string{"has-ghsa", "ghsa-only", "go-only"} {
		if !got[want] {
			t.Errorf("%s has a non-CVE advisory id that could be hiding a CVE; it must be queried", want)
		}
	}
}

// TestD146MaliciousAdvisoriesDoNotDriveHydration: a MAL- advisory belongs to
// VC-001, never reaches VC-008, and must not by itself buy a network request.
func TestD146MaliciousAdvisoriesDoNotDriveHydration(t *testing.T) {
	g, ctx := d146Graph(t, map[string][]datasource.Advisory{
		"mal-only": {{ID: "MAL-2024-1", Malicious: true}},
	})
	if c := aliasCandidates(g, ctx); len(c) != 0 {
		t.Errorf("a malicious-only package is not a hydration candidate, got %v", c)
	}
}

// TestD146UnversionedPackagesAreSkipped: /v1/query is keyed by name AND version;
// without one there is nothing to ask.
func TestD146UnversionedPackagesAreSkipped(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "n", Kind: graph.KindPackage, Ecosystem: "npm", Name: "n"})
	ctx := &check.Context{Graph: g, Advisories: map[string][]datasource.Advisory{
		"n": {{ID: "GHSA-aaaa-bbbb-cccc"}},
	}}
	if c := aliasCandidates(g, ctx); len(c) != 0 {
		t.Errorf("an unversioned node cannot be queried, got %v", c)
	}
}

// TestD146CleanPackagesAreSkipped is the shape of nearly every node in a real
// scan: no advisories at all, so no request.
func TestD146CleanPackagesAreSkipped(t *testing.T) {
	g, ctx := d146Graph(t, map[string][]datasource.Advisory{"clean": nil})
	if c := aliasCandidates(g, ctx); len(c) != 0 {
		t.Errorf("a package with no advisories is not a hydration candidate, got %v", c)
	}
}

// TestD146EachCoordinateAppearsOnce: /v1/query is per coordinate, so a package
// with several non-CVE advisories must still be one request.
func TestD146EachCoordinateAppearsOnce(t *testing.T) {
	g, ctx := d146Graph(t, map[string][]datasource.Advisory{
		"many": {{ID: "GHSA-a"}, {ID: "GHSA-b"}, {ID: "GO-2024-1"}},
	})
	if c := aliasCandidates(g, ctx); len(c) != 1 {
		t.Errorf("three non-CVE advisories on one package is one coordinate, got %v", c)
	}
}
