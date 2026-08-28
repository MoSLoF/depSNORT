package builtin

import (
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/graph"
)

// D-163 consumer-side pin: a maven-coordinate node with a Maven Central
// release history reaches the temporal checks like any other ecosystem — the
// check layer is ecosystem-neutral (D-24's coverage keys and D-03's
// extraction/judgment split both depend on that), and this guards it staying
// so. The jepsen shape: a JDBC driver pinned to a version published after a
// multi-year quiet stretch must produce the same VC-004 dormancy advisory it
// would as an npm package.
func TestDormancyFiresOnMavenHistory(t *testing.T) {
	id := "pkg:maven/org.postgresql/postgresql@42.7.4"
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "maven",
		Name: "org.postgresql:postgresql", Version: "42.7.4",
	})
	h := &datasource.ReleaseHistory{Package: "org.postgresql:postgresql", Ecosystem: "maven",
		Releases: []datasource.Release{
			{Version: "42.7.3", Published: time.Date(2021, 2, 1, 0, 0, 0, 0, time.UTC)},
			{Version: "42.7.4", Published: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
		}}
	h.Sort()

	fs := (Dormancy{}).Run(&check.Context{Graph: g, Now: nowRef,
		Releases: map[string]*datasource.ReleaseHistory{id: h}})
	if len(fs) != 1 {
		t.Fatalf("VC-004 findings on a maven history = %d, want 1", len(fs))
	}
	if fs[0].NodeID != id {
		t.Errorf("finding attached to %q, want %q", fs[0].NodeID, id)
	}
}
