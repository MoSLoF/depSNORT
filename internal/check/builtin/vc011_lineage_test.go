package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// lineageHistory: three releases at monthly intervals ending recently, with the
// publisher of each supplied by the caller. An empty string means "no identity
// recorded for that version".
func lineageHistory(publishers ...string) *datasource.ReleaseHistory {
	h := &datasource.ReleaseHistory{Package: "acme-widget", Ecosystem: "npm"}
	for i, who := range publishers {
		v := versionAt(i)
		published := nowRef.AddDate(0, -(len(publishers) - i), 0)
		h.Releases = append(h.Releases, datasource.Release{Version: v, Published: published})
		if who == "" {
			continue
		}
		if h.Publishers == nil {
			h.Publishers = map[string]datasource.Publisher{}
		}
		h.Publishers[v] = datasource.Publisher{ID: who, Name: who, Source: "npm._npmUser"}
	}
	h.Sort()
	return h
}

func versionAt(i int) string { return "1.0." + string(rune('0'+i)) }

func lineageCtx(h *datasource.ReleaseHistory, version string, withHook bool) *check.Context {
	id := "pkg:npm/acme-widget@" + version
	g := graph.New()
	n := g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "acme-widget", Version: version})
	if withHook {
		hook := g.AddNode(&graph.Node{ID: "hook:" + id + "#postinstall",
			Kind: graph.KindInstallHook, Ecosystem: "npm", Name: "postinstall"})
		g.AddEdge(n.ID, hook.ID, graph.EdgeDeclaresHook)
	}
	return &check.Context{Graph: g, Now: nowRef,
		Releases: map[string]*datasource.ReleaseHistory{id: h}}
}

func TestVC011FirstTimePublisherIsAdvisoryAlone(t *testing.T) {
	h := lineageHistory("alice", "alice", "mallory")
	fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), false))
	if len(fs) != 1 {
		t.Fatalf("VC-011 findings = %d, want 1", len(fs))
	}
	f := fs[0]
	// Maintainer handovers, co-maintainer first releases, and CI token
	// migrations all produce this. Gating on it alone would mute the check.
	if f.GateClass != finding.GateAdvisory {
		t.Errorf("gate class = %q, want advisory: actor change alone must not gate", f.GateClass)
	}
	if f.Axis != finding.AxisWeather {
		t.Errorf("axis = %q, want weather", f.Axis)
	}
	if !strings.Contains(f.Evidence, "mallory") {
		t.Errorf("evidence should name the publisher, got %q", f.Evidence)
	}
}

func TestVC011KnownPublisherIsSilent(t *testing.T) {
	h := lineageHistory("alice", "bob", "alice")
	if fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), false)); len(fs) != 0 {
		t.Errorf("VC-011 fired on a publisher who has shipped this package before: %+v", fs)
	}
}

// TestVC011NoPriorDataIsSilent is the honesty guard: "we cannot see who
// published the earlier versions" cannot support "this publisher is new".
func TestVC011NoPriorDataIsSilent(t *testing.T) {
	h := lineageHistory("", "", "mallory")
	if fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), false)); len(fs) != 0 {
		t.Errorf("VC-011 fired with no prior publisher data to compare against: %+v", fs)
	}
}

func TestVC011EcosystemWithoutPublishersIsSilent(t *testing.T) {
	h := lineageHistory("", "", "")
	if fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), false)); len(fs) != 0 {
		t.Errorf("VC-011 fired on an ecosystem that publishes no uploader: %+v", fs)
	}
}

func TestVC011FirstEverReleaseIsSilent(t *testing.T) {
	h := lineageHistory("alice")
	if fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(0), false)); len(fs) != 0 {
		t.Errorf("VC-011 fired on a package's first-ever release: %+v", fs)
	}
}

// TestVC011EscalatesWithInstallHook: a new actor plus install-time code is the
// shape that matters — the account that changed is the one whose next release
// runs on every consumer's machine.
func TestVC011EscalatesWithInstallHook(t *testing.T) {
	h := lineageHistory("alice", "alice", "mallory")
	fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), true))
	if len(fs) != 1 {
		t.Fatalf("VC-011 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible when composed with an install hook", fs[0].GateClass)
	}
	if fs[0].Severity != finding.SevHigh {
		t.Errorf("severity = %q, want high", fs[0].Severity)
	}
}

func TestVC011EscalatesWithDormancy(t *testing.T) {
	h := &datasource.ReleaseHistory{Package: "acme-widget", Ecosystem: "npm",
		Releases: []datasource.Release{
			{Version: "1.0.0", Published: nowRef.AddDate(-4, 0, 0)},
			{Version: "1.0.1", Published: nowRef.AddDate(-3, 0, 0)},
			{Version: "1.0.2", Published: nowRef.AddDate(0, 0, -10)},
		},
		Publishers: map[string]datasource.Publisher{
			"1.0.0": {ID: "alice", Name: "alice"},
			"1.0.1": {ID: "alice", Name: "alice"},
			"1.0.2": {ID: "mallory", Name: "mallory"},
		}}
	h.Sort()

	fs := (PublisherLineage{}).Run(lineageCtx(h, "1.0.2", false))
	if len(fs) != 1 {
		t.Fatalf("VC-011 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible for new publisher + dormancy", fs[0].GateClass)
	}
	if !strings.Contains(fs[0].Evidence, "dormancy") {
		t.Errorf("evidence should name the composition, got %q", fs[0].Evidence)
	}
}

// TestVC011StaleTransitionIsSilent: a handover years ago is settled history,
// not weather. Same recency floor as VC-004.
func TestVC011StaleTransitionIsSilent(t *testing.T) {
	old := nowRef.AddDate(-6, 0, 0)
	h := &datasource.ReleaseHistory{Package: "acme-widget", Ecosystem: "npm",
		Releases: []datasource.Release{
			{Version: "1.0.0", Published: old.AddDate(-1, 0, 0)},
			{Version: "1.0.1", Published: old},
		},
		Publishers: map[string]datasource.Publisher{
			"1.0.0": {ID: "alice", Name: "alice"},
			"1.0.1": {ID: "bob", Name: "bob"},
		}}
	h.Sort()

	if fs := (PublisherLineage{}).Run(lineageCtx(h, "1.0.1", true)); len(fs) != 0 {
		t.Errorf("VC-011 fired on a six-year-old handover: %+v", fs)
	}
}

func TestVC011NoReleaseDataIsSilent(t *testing.T) {
	ctx := lineageCtx(nil, "1.0.0", false)
	ctx.Releases = nil
	if fs := (PublisherLineage{}).Run(ctx); len(fs) != 0 {
		t.Errorf("VC-011 fired with no release data at all: %+v", fs)
	}
}

func TestVC011RecencyDecayIsSet(t *testing.T) {
	h := lineageHistory("alice", "alice", "mallory")
	fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), false))
	if len(fs) != 1 {
		t.Fatalf("VC-011 findings = %d, want 1", len(fs))
	}
	if fs[0].RecencyDecay <= 0 || fs[0].RecencyDecay > 1 {
		t.Errorf("recency decay = %v, want (0,1] on a weather-axis finding", fs[0].RecencyDecay)
	}
	// One month old against a 90-day half-life: still most of its weight.
	if fs[0].RecencyDecay < 0.5 {
		t.Errorf("recency decay = %v, want >0.5 for a one-month-old event",
			fs[0].RecencyDecay)
	}
}

// TestVC011PartialHistoryCannotClaimFirstTime is the DS-REV-04 guard. The
// history alice / unknown / mallory does NOT support "mallory has never
// published this package" — the unknown release could have been mallory's.
func TestVC011PartialHistoryCannotClaimFirstTime(t *testing.T) {
	h := lineageHistory("alice", "", "mallory")
	fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), false))
	if len(fs) != 1 {
		t.Fatalf("VC-011 findings = %d, want 1", len(fs))
	}
	f := fs[0]

	if strings.Contains(f.Title, "has not published this package before") {
		t.Errorf("title makes an unqualified first-time claim on a partial history: %q", f.Title)
	}
	if !strings.Contains(f.Evidence, "LOWER BOUND") {
		t.Errorf("evidence must state the limitation, got %q", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "record no publisher") {
		t.Errorf("evidence must say how much of the history is missing, got %q", f.Evidence)
	}
	if f.GateClass != finding.GateAdvisory {
		t.Errorf("gate class = %q, want advisory: partial evidence must not gate", f.GateClass)
	}
}

// TestVC011PartialHistoryDoesNotGateEvenWithAnInstallHook: composition
// multiplies confidence, and a partial history has none to multiply. This is
// the path that would otherwise produce a gate-eligible false positive.
func TestVC011PartialHistoryDoesNotGateEvenWithAnInstallHook(t *testing.T) {
	h := lineageHistory("alice", "", "mallory")
	fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), true))
	if len(fs) != 1 {
		t.Fatalf("VC-011 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass != finding.GateAdvisory {
		t.Errorf("gate class = %q; a partial history must stay advisory however it composes",
			fs[0].GateClass)
	}
	if fs[0].Severity == finding.SevHigh {
		t.Error("severity must be capped below high when the evidence is a lower bound")
	}
	// The composition is still reported — it is real context, just not grounds
	// to gate.
	if !strings.Contains(fs[0].Evidence, "install hook") {
		t.Errorf("evidence should still note the install hook, got %q", fs[0].Evidence)
	}
}

// TestVC011CompleteHistoryStillGates: the fix must not neuter the check where
// the evidence genuinely is complete.
func TestVC011CompleteHistoryStillGates(t *testing.T) {
	h := lineageHistory("alice", "alice", "mallory")
	fs := (PublisherLineage{}).Run(lineageCtx(h, versionAt(2), true))
	if len(fs) != 1 {
		t.Fatalf("VC-011 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass != finding.GateEligible || fs[0].Severity != finding.SevHigh {
		t.Errorf("complete history + install hook: gate=%q severity=%q, want gate-eligible/high",
			fs[0].GateClass, fs[0].Severity)
	}
	if !strings.Contains(fs[0].Title, "has not published this package before") {
		t.Errorf("a complete history supports the unqualified claim, got %q", fs[0].Title)
	}
}

func TestCapSeverity(t *testing.T) {
	// The reason this helper exists: Severity is a string type, so a naive
	// `sev > finding.SevMedium` compares "high" against "medium"
	// lexicographically and never fires.
	if finding.SevHigh > finding.SevMedium {
		t.Fatal("assumption changed: SevHigh now sorts after SevMedium as a string")
	}
	if got := capSeverity(finding.SevHigh, finding.SevMedium); got != finding.SevMedium {
		t.Errorf("capSeverity(high, medium) = %q, want medium", got)
	}
	if got := capSeverity(finding.SevLow, finding.SevMedium); got != finding.SevLow {
		t.Errorf("capSeverity(low, medium) = %q, want low unchanged", got)
	}
	if got := capSeverity(finding.SevCritical, finding.SevMedium); got != finding.SevMedium {
		t.Errorf("capSeverity(critical, medium) = %q, want medium", got)
	}
}
