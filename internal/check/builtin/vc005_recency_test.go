package builtin

import (
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
)

// Decision D-23. A second real workspace run produced 92 VC-005 findings, of
// which 82 described bursts that had already decayed out of relevance — 38 aged
// one to three years, 37 older than three years, and the oldest a release
// cluster from June 2015 reported as supply-chain weather in 2026.
//
// These tests pin the boundary from both sides: a burst inside the window must
// still fire, and an old one must not survive by any path, including the
// install-hook composition that would otherwise escalate it to gate-eligible.

// slowPackageBurst builds a package with a slow cadence (so the burst is
// genuinely anomalous) whose burst lands at `at`.
func slowPackageBurst(pkg string, at time.Time) *datasource.ReleaseHistory {
	h := &datasource.ReleaseHistory{Package: pkg, Ecosystem: "npm"}
	// Quarterly cadence establishes "slow" well past burstMinCadence.
	for i := 12; i > 0; i-- {
		h.Releases = append(h.Releases, datasource.Release{
			Version:   "1.0." + string(rune('0'+i%10)),
			Published: at.Add(-time.Duration(i) * 90 * 24 * time.Hour),
		})
	}
	for i := 0; i < 4; i++ {
		h.Releases = append(h.Releases, datasource.Release{
			Version:   "2.0." + string(rune('0'+i)),
			Published: at.Add(time.Duration(i) * 3 * time.Hour),
		})
	}
	h.Sort()
	return h
}

func TestVC005ReportsBurstInsideTheDecayWindow(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	at := now.Add(-120 * 24 * time.Hour) // decay ~0.40, comfortably live

	g := nodeWith("pkg:npm/slowpkg@2.0.0", "slowpkg", "2.0.0", false)
	fs := (PatchBurst{}).Run(&check.Context{
		Graph: g, Now: now,
		Releases: map[string]*datasource.ReleaseHistory{
			"pkg:npm/slowpkg@2.0.0": slowPackageBurst("slowpkg", at),
		},
	})
	if len(fs) != 1 {
		t.Fatalf("a 120-day-old burst on a quarterly package must still be reported, got %d findings", len(fs))
	}
	if fs[0].RecencyDecay < burstMinDecay {
		t.Errorf("reported finding carries decay %.3f, below its own floor %.2f",
			fs[0].RecencyDecay, burstMinDecay)
	}
}

func TestVC005IgnoresBurstsOutsideTheDecayWindow(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)

	// Ages drawn from the real distribution that motivated D-23.
	for _, ageDays := range []int{400, 1000, 2905, 4164} {
		at := now.Add(-time.Duration(ageDays) * 24 * time.Hour)
		g := nodeWith("pkg:npm/oldpkg@2.0.0", "oldpkg", "2.0.0", false)
		fs := (PatchBurst{}).Run(&check.Context{
			Graph: g, Now: now,
			Releases: map[string]*datasource.ReleaseHistory{
				"pkg:npm/oldpkg@2.0.0": slowPackageBurst("oldpkg", at),
			},
		})
		if len(fs) != 0 {
			t.Errorf("a %dd-old burst is climate history, not weather: got %d findings (%q)",
				ageDays, len(fs), fs[0].Evidence)
		}
	}
}

// An install hook is what escalates VC-005 to gate-eligible. The recency floor
// must sit UPSTREAM of that escalation, or a decade-old burst on a package with
// a hook would still be able to fail a build under -fail-on-eligible.
func TestVC005RecencyFloorPrecedesHookEscalation(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	at := now.Add(-2905 * 24 * time.Hour)

	g := nodeWith("pkg:npm/oldhook@2.0.0", "oldhook", "2.0.0", true)
	fs := (PatchBurst{}).Run(&check.Context{
		Graph: g, Now: now,
		Releases: map[string]*datasource.ReleaseHistory{
			"pkg:npm/oldhook@2.0.0": slowPackageBurst("oldhook", at),
		},
	})
	if len(fs) != 0 {
		t.Fatalf("an 8-year-old burst must not reach gate-eligible via the hook path: got %+v", fs[0])
	}
}
