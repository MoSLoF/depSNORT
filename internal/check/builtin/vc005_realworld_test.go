package builtin

import (
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// Observed on a real 59-repo workspace: VC-005 produced 176 gate-eligible
// findings, dominated by ordinary release trains. `@angular/*` ships ~20
// packages together several times a week; `vite`, `undici` and `picomatch`
// release on similar cadences. Every one of these was a false positive, and at
// gate-eligible they would have failed a build for a monorepo doing its job.
//
// The original anomaly test was `median > 24h`, which nearly every maintained
// package clears. Bursts are simply COMMON — the signal cannot stand alone.

// releaseTrain builds a history for a package that genuinely releases often.
func releaseTrain(pkg string, medianDays float64, burstCount int, at time.Time) *datasource.ReleaseHistory {
	h := &datasource.ReleaseHistory{Package: pkg, Ecosystem: "npm"}
	// Long, regular history establishing the cadence.
	for i := 30; i > 0; i-- {
		h.Releases = append(h.Releases, datasource.Release{
			Version:   "0.0." + string(rune('0'+i%10)),
			Published: at.Add(-time.Duration(float64(i)*medianDays*24) * time.Hour),
		})
	}
	// The burst itself, clustered at `at`.
	for i := 0; i < burstCount; i++ {
		h.Releases = append(h.Releases, datasource.Release{
			Version:   "19.2." + string(rune('0'+i)),
			Published: at.Add(time.Duration(i) * 3 * time.Hour),
		})
	}
	h.Sort()
	return h
}

func nodeWith(id, name, ver string, hook bool) *graph.Graph {
	g := graph.New()
	attr := map[string]string{}
	if hook {
		attr["npm.hasInstallScript"] = "true"
	}
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: name, Version: ver, Attr: attr})
	return g
}

func TestVC005IgnoresOrdinaryReleaseTrains(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	at := now.Add(-90 * 24 * time.Hour)

	// Cadences taken verbatim from the real report's evidence strings.
	cases := []struct {
		name       string
		medianDays float64
		burst      int
	}{
		{"@angular/animations", 1, 4},
		{"@angular/core", 1, 4},
		{"vite", 1, 5},
		{"undici", 4, 3},
		{"h3", 5, 3},
		{"impound", 3, 3},
	}
	for _, c := range cases {
		id := "pkg:npm/" + c.name + "@19.2.21"
		g := nodeWith(id, c.name, "19.2.21", false)
		h := releaseTrain(c.name, c.medianDays, c.burst, at)
		// Pin the scanned version to one inside the burst.
		h.Releases[len(h.Releases)-1].Version = "19.2.21"
		ctx := &check.Context{Graph: g, Now: now,
			Releases: map[string]*datasource.ReleaseHistory{id: h}}
		if f := (PatchBurst{}).Run(ctx); len(f) > 0 {
			t.Errorf("%s (releases every ~%.0fd) should not be flagged: %s",
				c.name, c.medianDays, f[0].Evidence)
		}
	}
}

// A genuinely dormant package that suddenly emits a cluster IS the signal.
func TestVC005StillCatchesDormantPackageBurst(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	at := now.Add(-10 * 24 * time.Hour)
	id := "pkg:npm/sleepy-lib@1.0.4"
	g := nodeWith(id, "sleepy-lib", "1.0.4", false)
	h := releaseTrain("sleepy-lib", 120, 4, at) // ships twice a year, then 4 in a day
	h.Releases[len(h.Releases)-1].Version = "1.0.4"

	f := (PatchBurst{}).Run(&check.Context{Graph: g, Now: now,
		Releases: map[string]*datasource.ReleaseHistory{id: h}})
	if len(f) == 0 {
		t.Fatal("a dormant package emitting a burst must still be flagged")
	}
	if f[0].GateClass != finding.GateAdvisory {
		t.Errorf("a burst ALONE must be advisory, got %s", f[0].GateClass)
	}
}

// Composition is what earns gating: a burst on a package that also runs install
// hooks is the ChainDrop shape, not a release train.
func TestVC005EscalatesOnlyWhenComposed(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	at := now.Add(-10 * 24 * time.Hour)
	h := releaseTrain("wormy-lib", 120, 4, at)
	h.Releases[len(h.Releases)-1].Version = "1.0.4"
	hist := map[string]*datasource.ReleaseHistory{"pkg:npm/wormy-lib@1.0.4": h}

	plain := (PatchBurst{}).Run(&check.Context{
		Graph: nodeWith("pkg:npm/wormy-lib@1.0.4", "wormy-lib", "1.0.4", false),
		Now:   now, Releases: hist})
	hooked := (PatchBurst{}).Run(&check.Context{
		Graph: nodeWith("pkg:npm/wormy-lib@1.0.4", "wormy-lib", "1.0.4", true),
		Now:   now, Releases: hist})

	if len(plain) == 0 || len(hooked) == 0 {
		t.Fatal("expected findings in both cases")
	}
	if plain[0].GateClass != finding.GateAdvisory {
		t.Errorf("uncomposed burst gate = %s, want advisory", plain[0].GateClass)
	}
	if hooked[0].GateClass != finding.GateEligible {
		t.Errorf("burst + install hook gate = %s, want gate-eligible", hooked[0].GateClass)
	}
	if hooked[0].Confidence <= plain[0].Confidence {
		t.Error("composition should raise confidence")
	}
}
