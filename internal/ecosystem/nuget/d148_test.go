package nuget

import (
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// D-148: a dependency missing from the NuGet cache was disclosed only when the
// cache-dir list itself was non-empty. With no NUGET_PACKAGES and no resolvable
// home directory — the environment where NOTHING can be examined — every miss
// was silent, reporting the least-covered scan as the cleanest.
func TestD148EmptyCacheDirListStillDiscloses(t *testing.T) {
	g := graph.New()
	n := g.AddNode(&graph.Node{
		ID: "pkg:nuget/Serilog@3.0.1", Kind: graph.KindPackage,
		Ecosystem: "nuget", Name: "Serilog", Version: "3.0.1",
	})
	var gaps instsurf.Gaps
	scanDependencyPkg(g, n, nil, &gaps) // no cache dirs at all
	list := gaps.List()
	if len(list) != 1 || list[0].Reason != instsurf.GapUnavailable {
		t.Fatalf("an unexaminable dependency must be disclosed even with nowhere to look, got %v", list)
	}
}
