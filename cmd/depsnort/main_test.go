package main

import (
	"context"
	"testing"

	"ihbv.io/depsnort/internal/expand"
)

// TestUseAssertedTier locks in OPU-12 D-2: the deps.dev asserted tier is default
// on, suppressed by -no-depsdev, and impossible under -offline (no network),
// where the walk falls back to presumed versions.
func TestUseAssertedTier(t *testing.T) {
	cases := []struct {
		depsDev, noDepsDev, offline, want bool
	}{
		{true, false, false, true},   // default scan → asserted
		{true, true, false, false},   // -no-depsdev → presumed
		{true, false, true, false},   // -offline → presumed (no network)
		{true, true, true, false},    // both → presumed
		{false, false, false, false}, // explicit -depsdev=false → presumed
	}
	for _, c := range cases {
		if got := useAssertedTier(c.depsDev, c.noDepsDev, c.offline); got != c.want {
			t.Errorf("useAssertedTier(depsDev=%v,noDepsDev=%v,offline=%v) = %v, want %v",
				c.depsDev, c.noDepsDev, c.offline, got, c.want)
		}
	}
	if presumedClosureNote == "" {
		t.Error("presumedClosureNote must be a non-empty in-report caveat")
	}
}

// recordingResolver notes each ecosystem it was asked to resolve.
type recordingResolver struct {
	name  string
	calls *[]string
}

func (r recordingResolver) Name() string { return r.name }
func (r recordingResolver) Resolve(_ context.Context, eco, _, _ string) (expand.ResolvedGraph, bool, error) {
	*r.calls = append(*r.calls, r.name+":"+eco)
	return expand.ResolvedGraph{}, false, nil
}

// TestAssertedResolverRouting locks in OPU-13 D-2: gomod routes to the goproxy
// resolver and NEVER to deps.dev (criterion #5); other ecosystems route to
// deps.dev; and each is attributed to the backend that answered.
func TestAssertedResolverRouting(t *testing.T) {
	var ddCalls, goCalls []string
	a := assertedResolver{
		depsDev: recordingResolver{name: "deps.dev", calls: &ddCalls},
		gomod:   recordingResolver{name: "go-proxy", calls: &goCalls},
	}
	ctx := context.Background()
	a.Resolve(ctx, "gomod", "github.com/x/y", "v1.0.0")
	a.Resolve(ctx, "pypi", "flask", "2.0.0")
	a.Resolve(ctx, "cargo", "serde", "1.0.0")

	if len(goCalls) != 1 || goCalls[0] != "go-proxy:gomod" {
		t.Errorf("gomod routing = %v, want [go-proxy:gomod]", goCalls)
	}
	for _, c := range ddCalls {
		if c == "deps.dev:gomod" {
			t.Error("deps.dev was called for a gomod coordinate — criterion #5 violated")
		}
	}
	if len(ddCalls) != 2 {
		t.Errorf("deps.dev calls = %v, want the two non-Go ecosystems", ddCalls)
	}
	// Attribution: Go → go-proxy, everything else → deps.dev.
	if a.NameFor("gomod") != "go-proxy" {
		t.Errorf("NameFor(gomod) = %q, want go-proxy", a.NameFor("gomod"))
	}
	if a.NameFor("pypi") != "deps.dev" {
		t.Errorf("NameFor(pypi) = %q, want deps.dev", a.NameFor("pypi"))
	}
}
