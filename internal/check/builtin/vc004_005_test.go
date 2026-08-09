package builtin

import (
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

var nowRef = time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)

func rel(v string, t time.Time) datasource.Release {
	return datasource.Release{Version: v, Published: t}
}

// burstHistory: a package that normally ships every ~6 months, then emits four
// releases in one morning — the republish signature.
func burstHistory() *datasource.ReleaseHistory {
	base := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	h := &datasource.ReleaseHistory{Package: "burst-pkg", Ecosystem: "npm", Releases: []datasource.Release{
		rel("1.0.0", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
		rel("1.0.1", time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)),
		rel("1.0.2", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
		rel("1.0.3", base),
		rel("1.0.4", base.Add(time.Hour)),
		rel("1.0.5", base.Add(2*time.Hour)),
	}}
	h.Sort()
	return h
}

func nodeGraph(id, name, ver string, attr map[string]string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: name, Version: ver, Attr: attr})
	return g
}

func TestPatchBurstFiresOnAnomalousCluster(t *testing.T) {
	id := "pkg:npm/burst-pkg@1.0.5"
	g := nodeGraph(id, "burst-pkg", "1.0.5", nil)
	ctx := &check.Context{Graph: g, Now: nowRef,
		Releases: map[string]*datasource.ReleaseHistory{id: burstHistory()}}

	fs := (PatchBurst{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("VC-005 findings = %d, want 1", len(fs))
	}
	f := fs[0]
	// A burst ALONE is advisory: release bursts are common and benign, so only
	// composition with another signal earns the gate (see vc005_realworld_test).
	if f.GateClass != finding.GateAdvisory || f.Axis != finding.AxisWeather {
		t.Errorf("finding = %+v", f)
	}
	// Recent event -> decay near 1.
	if f.RecencyDecay < 0.9 {
		t.Errorf("recency decay = %v, want near 1 for a 3-day-old event", f.RecencyDecay)
	}
}

func TestPatchBurstComposesWithInstallHook(t *testing.T) {
	id := "pkg:npm/burst-pkg@1.0.5"
	plain := nodeGraph(id, "burst-pkg", "1.0.5", nil)
	hooked := nodeGraph(id, "burst-pkg", "1.0.5", map[string]string{"npm.hasInstallScript": "true"})
	hist := map[string]*datasource.ReleaseHistory{id: burstHistory()}

	a := (PatchBurst{}).Run(&check.Context{Graph: plain, Now: nowRef, Releases: hist})
	b := (PatchBurst{}).Run(&check.Context{Graph: hooked, Now: nowRef, Releases: hist})
	if len(a) != 1 || len(b) != 1 {
		t.Fatal("expected one finding each")
	}
	if b[0].Confidence <= a[0].Confidence {
		t.Errorf("install-hook composition did not raise confidence: %v vs %v",
			b[0].Confidence, a[0].Confidence)
	}
}

func TestPatchBurstQuietForSteadyCadence(t *testing.T) {
	// A package that genuinely ships several times a day must produce NO finding
	// at all — clustering is expected at that cadence and carries no signal.
	base := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	h := &datasource.ReleaseHistory{Releases: []datasource.Release{
		rel("1.0.0", base.Add(-6*time.Hour)),
		rel("1.0.1", base.Add(-4*time.Hour)),
		rel("1.0.2", base.Add(-2*time.Hour)),
		rel("1.0.3", base),
	}}
	h.Sort()
	id := "pkg:npm/fast@1.0.3"
	g := nodeGraph(id, "fast", "1.0.3", nil)
	fs := (PatchBurst{}).Run(&check.Context{Graph: g, Now: nowRef,
		Releases: map[string]*datasource.ReleaseHistory{id: h}})
	if len(fs) != 0 {
		t.Errorf("a fast-shipping package should produce no burst finding, got %d: %s",
			len(fs), fs[0].Evidence)
	}
}

func TestPatchBurstNoDataIsQuiet(t *testing.T) {
	g := nodeGraph("pkg:npm/x@1.0.0", "x", "1.0.0", nil)
	if fs := (PatchBurst{}).Run(&check.Context{Graph: g, Now: nowRef}); len(fs) != 0 {
		t.Errorf("no release data should produce no findings, got %d", len(fs))
	}
}

func TestDormancyAdvisoryByDefaultEscalatesWithHook(t *testing.T) {
	id := "pkg:npm/sleepy@2.0.0"
	h := &datasource.ReleaseHistory{Releases: []datasource.Release{
		rel("1.0.0", time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
		rel("2.0.0", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)),
	}}
	h.Sort()
	hist := map[string]*datasource.ReleaseHistory{id: h}

	plain := (Dormancy{}).Run(&check.Context{
		Graph: nodeGraph(id, "sleepy", "2.0.0", nil), Now: nowRef, Releases: hist})
	if len(plain) != 1 {
		t.Fatalf("VC-004 findings = %d, want 1", len(plain))
	}
	if plain[0].GateClass != finding.GateAdvisory {
		t.Errorf("dormancy alone must be advisory, got %s", plain[0].GateClass)
	}

	hooked := (Dormancy{}).Run(&check.Context{
		Graph:    nodeGraph(id, "sleepy", "2.0.0", map[string]string{"npm.hasInstallScript": "true"}),
		Now:      nowRef,
		Releases: hist})
	if hooked[0].GateClass != finding.GateEligible {
		t.Errorf("dormancy + install hook should escalate to gate-eligible, got %s", hooked[0].GateClass)
	}
}

func TestDormancyQuietForActivePackage(t *testing.T) {
	id := "pkg:npm/active@1.0.2"
	h := &datasource.ReleaseHistory{Releases: []datasource.Release{
		rel("1.0.0", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)),
		rel("1.0.1", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)),
		rel("1.0.2", time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)),
	}}
	h.Sort()
	fs := (Dormancy{}).Run(&check.Context{Graph: nodeGraph(id, "active", "1.0.2", nil),
		Now: nowRef, Releases: map[string]*datasource.ReleaseHistory{id: h}})
	if len(fs) != 0 {
		t.Errorf("actively maintained package should not trip dormancy, got %d", len(fs))
	}
}

func TestDecayReducesRecentEventWeight(t *testing.T) {
	// An awakening ~4 months old: still inside the reporting window, but its
	// weight is visibly reduced by decay.
	id := "pkg:npm/semirecent@2.0.0"
	h := &datasource.ReleaseHistory{Releases: []datasource.Release{
		rel("1.0.0", time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
		rel("2.0.0", time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)),
	}}
	h.Sort()
	fs := (Dormancy{}).Run(&check.Context{Graph: nodeGraph(id, "semirecent", "2.0.0", nil),
		Now: nowRef, Releases: map[string]*datasource.ReleaseHistory{id: h}})
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding for a ~4-month-old awakening, got %d", len(fs))
	}
	if d := fs[0].RecencyDecay; d >= 1 || d < 0.3 {
		t.Errorf("recency decay = %v, want between 0.3 and 1", d)
	}
	if fs[0].Score() >= 0.5 {
		t.Errorf("score = %v, want reduced by decay", fs[0].Score())
	}
}

// A real workspace produced 687 VC-004 findings — a fifth of all packages —
// because any year-long gap ANYWHERE in a package's history qualified,
// including gaps that closed years ago. The axis is recent-compromise weather,
// so a long-settled awakening is out of scope.
func TestDormancyIgnoresLongSettledAwakenings(t *testing.T) {
	id := "pkg:npm/stable-lib@2.0.0"
	h := &datasource.ReleaseHistory{Releases: []datasource.Release{
		rel("1.0.0", time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		rel("2.0.0", time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)), // 3y gap, but 7y ago
	}}
	h.Sort()
	fs := (Dormancy{}).Run(&check.Context{Graph: nodeGraph(id, "stable-lib", "2.0.0", nil),
		Now: nowRef, Releases: map[string]*datasource.ReleaseHistory{id: h}})
	if len(fs) != 0 {
		t.Errorf("a 7-year-old awakening is history, not weather; got %d finding(s): %s",
			len(fs), fs[0].Evidence)
	}
}
