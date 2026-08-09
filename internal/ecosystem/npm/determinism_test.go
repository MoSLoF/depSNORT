package npm

import (
	"testing"
)

// Go randomizes map iteration order on purpose. The lockfile's `packages` object
// decodes into a map, so ranging it directly leaked randomness into edge
// insertion order — two identical scans emitted the same edges in different
// orders, which breaks the reproducible-CI-gate requirement (Decision D-09).
// This caught it; keep it.
func TestResolveIsDeterministic(t *testing.T) {
	a := &Adapter{}
	const runs = 12

	var first []string
	for i := 0; i < runs; i++ {
		g, err := a.Resolve("testdata/realworld")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		var seq []string
		for _, e := range g.SortedEdges() {
			seq = append(seq, e.From+" -"+string(e.Type)+"-> "+e.To)
		}
		if i == 0 {
			first = seq
			continue
		}
		if len(seq) != len(first) {
			t.Fatalf("run %d produced %d edges, first run produced %d", i, len(seq), len(first))
		}
		for j := range seq {
			if seq[j] != first[j] {
				t.Fatalf("run %d edge %d differs:\n  got  %s\n  want %s", i, j, seq[j], first[j])
			}
		}
	}
}

func TestSortedEdgesIsStableAcrossGraphs(t *testing.T) {
	a := &Adapter{}
	g1, err := a.Resolve("testdata/proj")
	if err != nil {
		t.Fatal(err)
	}
	g2, err := a.Resolve("testdata/proj")
	if err != nil {
		t.Fatal(err)
	}
	e1, e2 := g1.SortedEdges(), g2.SortedEdges()
	if len(e1) != len(e2) {
		t.Fatalf("edge counts differ: %d vs %d", len(e1), len(e2))
	}
	for i := range e1 {
		if e1[i] != e2[i] {
			t.Errorf("edge %d differs: %+v vs %+v", i, e1[i], e2[i])
		}
	}
}
