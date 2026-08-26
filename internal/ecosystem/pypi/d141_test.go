package pypi

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

// d141RefusingDoer fails the test if any HTTP request is attempted.
type d141RefusingDoer struct{ t *testing.T }

func (d d141RefusingDoer) Do(*http.Request) (*http.Response, error) {
	d.t.Error("offline must not issue an HTTP request")
	return nil, errors.New("refused")
}

// D-141: -offline used to construct the PyPI adapter with NO sdist fetcher at
// all. Two things followed, both wrong. Cached sdists went unanalyzed even
// though the fetcher serves from cache offline and refuses the network on its
// own. And every dependency's install surface was skipped SILENTLY — the run
// still reported "0 partial install-surface extraction(s)", a skip rendered as
// an absence, which is the R-01 invisibility this codebase refuses.
//
// The fetcher is now passed through with its offline flag set, so a cache hit
// is analyzed and a cache miss is a disclosed gap.

func d141Graph(t *testing.T) (*graph.Graph, string) {
	t.Helper()
	g := graph.New()
	id := "pkg:pypi/six@1.16.0"
	g.AddNode(&graph.Node{ID: id, Ecosystem: "pypi", Name: "six", Version: "1.16.0"})
	return g, id
}

// TestD141OfflineKeepsTheFetcher is the constructor contract. Dropping the
// fetcher is what produced both failures, so the presence of one offline is
// the thing worth pinning.
func TestD141OfflineKeepsTheFetcher(t *testing.T) {
	cache := datasource.NewCache(t.TempDir(), time.Hour)
	if a := NewWithSdist(cache, true /* offline */); a.Sdist == nil {
		t.Fatal("offline must keep the sdist fetcher: it serves from cache and gates the network itself")
	}
	if a := NewWithSdist(cache, false); a.Sdist == nil {
		t.Fatal("online adapter must have a fetcher")
	}
}

// TestD141OfflineCacheMissIsDisclosed: with a cold cache, an offline scan can
// examine nothing — and must say so rather than report clean coverage.
func TestD141OfflineCacheMissIsDisclosed(t *testing.T) {
	a := NewWithSdist(datasource.NewCache(t.TempDir(), time.Hour), true)
	g, id := d141Graph(t)

	err := a.ExtractInstallSurface(t.TempDir(), g)
	if err == nil {
		t.Fatal("an offline cache miss leaves the install surface unexamined; that must be a gap, not silence")
	}
	gaps := instsurf.GapsOf(err)
	if len(gaps) != 1 || gaps[0].Package != id {
		t.Fatalf("expected one gap naming the unexamined package, got %v", gaps)
	}
	// No hook may be invented for a package whose source was never read.
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook {
			t.Errorf("unexpected hook %q for an unexamined package", n.Name)
		}
	}
}

// TestD141OfflineNeverTouchesTheNetwork guards the reason keeping the fetcher
// is safe. If the offline flag did not reach it, this would attempt a real
// request; the stub fails the test if it is ever called.
func TestD141OfflineNeverTouchesTheNetwork(t *testing.T) {
	a := NewWithSdist(datasource.NewCache(t.TempDir(), time.Hour), true)
	a.Sdist.HTTP = d141RefusingDoer{t: t}
	g, _ := d141Graph(t)
	// Errors are expected (cache miss); the assertion is inside the stub.
	_ = a.ExtractInstallSurface(t.TempDir(), g)
}
