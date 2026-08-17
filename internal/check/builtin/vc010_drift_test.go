package builtin

import (
	"strings"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/baseline"
	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/profile"
)

// driftCtx wires a one-package graph against a baseline profile and a candidate
// profile, the way `scan -baseline` does.
func driftCtx(baseProf, candidate profile.Profile) *check.Context {
	g := graph.New()
	n := g.AddNode(&graph.Node{
		ID: candidate.PURL, Kind: graph.KindPackage, Ecosystem: candidate.Ecosystem,
		Name: candidate.Name, Version: candidate.Version,
	})
	g.MarkRoot("pkg:npm/app@1.0.0")
	return &check.Context{
		Graph:    g,
		Now:      nowRef,
		Baseline: map[string]profile.Profile{baseline.Key(baseProf.Ecosystem, baseProf.Name): baseProf},
		Profiles: map[string]profile.Profile{n.ID: candidate},
	}
}

func driftProf(version string, caps, hooks, sinks []string) profile.Profile {
	return profile.Profile{
		Schema: profile.Schema, PURL: "pkg:npm/acme-widget@" + version,
		Ecosystem: "npm", Name: "acme-widget", Version: version,
		Caps: caps, Hooks: hooks, Sinks: sinks,
	}
}

func TestVC010SilentWithoutABaseline(t *testing.T) {
	ctx := driftCtx(driftProf("1.2.3", nil, nil, nil), driftProf("1.2.4", []string{"network"}, nil, nil))
	ctx.Baseline = nil
	if fs := (CapabilityDrift{}).Run(ctx); len(fs) != 0 {
		t.Errorf("VC-010 fired with no baseline: %+v", fs)
	}
}

func TestVC010SilentWhenNothingChanged(t *testing.T) {
	base := driftProf("1.2.3", []string{"exec"}, []string{"postinstall"}, nil)
	same := driftProf("1.2.4", []string{"exec"}, []string{"postinstall"}, nil)
	if fs := (CapabilityDrift{}).Run(driftCtx(base, same)); len(fs) != 0 {
		t.Errorf("VC-010 fired on an unchanged capability set: %+v", fs)
	}
}

// TestVC010SilentOnNewPackage: a package absent from the baseline is NEW, not
// drifted. Reporting it here would drown the real signal in every added dep.
func TestVC010SilentOnNewPackage(t *testing.T) {
	ctx := driftCtx(driftProf("1.2.3", nil, nil, nil), driftProf("1.2.4", []string{"network"}, nil, nil))
	ctx.Baseline = map[string]profile.Profile{
		baseline.Key("npm", "some-other-package"): driftProf("1.0.0", nil, nil, nil),
	}
	if fs := (CapabilityDrift{}).Run(ctx); len(fs) != 0 {
		t.Errorf("VC-010 fired on a package the baseline never saw: %+v", fs)
	}
}

// TestVC010PatchAddingCredentialsGates is the core case: a release that claims
// nothing structural changed, that acquired credential access.
func TestVC010PatchAddingCredentialsGates(t *testing.T) {
	base := driftProf("1.2.3", []string{"exec"}, []string{"postinstall"}, nil)
	next := driftProf("1.2.4", []string{"exec", "credentials", "network"},
		[]string{"postinstall"}, []string{"NPM_TOKEN"})

	fs := (CapabilityDrift{}).Run(driftCtx(base, next))
	if len(fs) != 1 {
		t.Fatalf("VC-010 findings = %d, want 1", len(fs))
	}
	f := fs[0]
	if f.GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible", f.GateClass)
	}
	if f.Severity != finding.SevHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Axis != finding.AxisDrift {
		t.Errorf("axis = %q, want drift", f.Axis)
	}
	if !strings.Contains(f.Evidence, "credentials") || !strings.Contains(f.Evidence, "NPM_TOKEN") {
		t.Errorf("evidence should name what arrived, got %q", f.Evidence)
	}
}

// TestVC010MajorReleaseDoesNotGate: a major version makes no claim that nothing
// changed, so the same addition is ordinary. Still reported.
func TestVC010MajorReleaseDoesNotGate(t *testing.T) {
	base := driftProf("1.2.3", []string{"exec"}, []string{"postinstall"}, nil)
	next := driftProf("2.0.0", []string{"exec", "network"}, []string{"postinstall"}, nil)

	fs := (CapabilityDrift{}).Run(driftCtx(base, next))
	if len(fs) != 1 {
		t.Fatalf("VC-010 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass != finding.GateAdvisory {
		t.Errorf("gate class = %q, want advisory on a major bump", fs[0].GateClass)
	}
}

// TestVC010NeverBlocks: the baseline side of the comparison is a file this tool
// cannot verify, so gate-eligible is the honest ceiling.
func TestVC010NeverBlocks(t *testing.T) {
	base := driftProf("1.2.3", nil, nil, nil)
	worst := driftProf("1.2.4",
		[]string{"credentials", "network", "cradle", "obfuscation", "exec"},
		[]string{"preinstall", "postinstall"},
		[]string{"NPM_TOKEN", "AWS_SECRET_ACCESS_KEY"})

	fs := (CapabilityDrift{}).Run(driftCtx(base, worst))
	if len(fs) != 1 {
		t.Fatalf("VC-010 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass == finding.GateBlock {
		t.Error("VC-010 must never emit a block-class finding: it rests on an operator-supplied baseline")
	}
}

// TestVC010RemovalIsNotEscalation: a release that DROPS a hook has drifted, but
// not in a direction worth an operator's attention.
func TestVC010RemovalIsNotEscalation(t *testing.T) {
	base := driftProf("1.2.3", []string{"exec", "network"}, []string{"postinstall"}, nil)
	next := driftProf("1.2.4", []string{"exec"}, nil, nil)
	if fs := (CapabilityDrift{}).Run(driftCtx(base, next)); len(fs) != 0 {
		t.Errorf("VC-010 fired on a release that only removed capability: %+v", fs)
	}
}

// TestVC010NewHookAloneEscalates: an install hook whose source could not be read
// contributes no capability, which is exactly when the capability list is a
// lower bound.
func TestVC010NewHookAloneEscalates(t *testing.T) {
	base := driftProf("1.2.3", nil, nil, nil)
	next := driftProf("1.2.4", nil, []string{"postinstall"}, nil)
	next.Unobserved = []string{profile.UnobservedInstallSurface}

	fs := (CapabilityDrift{}).Run(driftCtx(base, next))
	if len(fs) != 1 {
		t.Fatalf("VC-010 findings = %d, want 1", len(fs))
	}
	if fs[0].GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible for a newly declared hook", fs[0].GateClass)
	}
	if !strings.Contains(fs[0].Evidence, "LOWER BOUND") {
		t.Errorf("evidence must disclose that the delta is a lower bound, got %q", fs[0].Evidence)
	}
}

// TestVC010ComposesWithLineageAndDormancy is the success criterion the market
// review named: one finding that states the capability change, the actor
// change, and the temporal context together, rather than making an operator
// cross-reference three.
func TestVC010ComposesWithLineageAndDormancy(t *testing.T) {
	base := driftProf("1.6.2", nil, nil, nil)
	base.Publisher = datasource.Publisher{ID: "alice", Name: "alice", Source: "npm._npmUser"}
	next := driftProf("1.6.3", []string{"credentials", "network"}, []string{"postinstall"}, nil)
	next.Publisher = datasource.Publisher{ID: "mallory", Name: "mallory", Source: "npm._npmUser"}

	ctx := driftCtx(base, next)
	dormant := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	woke := dormant.AddDate(0, 0, 420)
	ctx.Releases = map[string]*datasource.ReleaseHistory{
		next.PURL: {
			Package: "acme-widget", Ecosystem: "npm",
			Releases: []datasource.Release{
				{Version: "1.6.2", Published: dormant},
				{Version: "1.6.3", Published: woke},
			},
		},
	}

	fs := (CapabilityDrift{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("VC-010 findings = %d, want 1", len(fs))
	}
	ev := fs[0].Evidence
	for _, want := range []string{"postinstall", "credentials", "mallory", "alice", "dormancy"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence missing %q; the point of the drift axis is one composed claim:\n%s", want, ev)
		}
	}
}

func TestVC010UnknownPublisherIsDisclosedNotAssumed(t *testing.T) {
	base := driftProf("1.2.3", nil, nil, nil)
	next := driftProf("1.2.4", []string{"network"}, nil, nil)
	next.Publisher = datasource.Publisher{ID: "alice", Name: "alice"}

	fs := (CapabilityDrift{}).Run(driftCtx(base, next))
	if len(fs) != 1 {
		t.Fatalf("VC-010 findings = %d, want 1", len(fs))
	}
	if !strings.Contains(fs[0].Evidence, "unevaluated") {
		t.Errorf("a one-sided publisher identity must be disclosed as unevaluated, got %q", fs[0].Evidence)
	}
}
