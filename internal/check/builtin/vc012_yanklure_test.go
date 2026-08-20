package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// yankRel is a release with a yank flag, for building test histories.
type yankRel struct {
	ver    string
	yanked bool
}

func cargoNodeGraph(name, ver string) (*graph.Graph, string) {
	id := "pkg:cargo/" + name + "@" + ver
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "cargo", Name: name, Version: ver})
	return g, id
}

func yankHistory(pkg string, rels ...yankRel) *datasource.ReleaseHistory {
	h := &datasource.ReleaseHistory{Package: pkg, Ecosystem: "cargo"}
	for _, r := range rels {
		h.Releases = append(h.Releases, datasource.Release{Version: r.ver, Yanked: r.yanked})
	}
	return h
}

func runYankLure(g *graph.Graph, id string, h *datasource.ReleaseHistory) []finding.Finding {
	return (YankLure{}).Run(&check.Context{
		Graph:    g,
		Releases: map[string]*datasource.ReleaseHistory{id: h},
	})
}

// The arrayref incident: pinned to a yanked version, and the crate's live newest
// (0.3.10) sits atop a run of yanked versions — the yank-lure shape. Must fire
// HIGH / gate-eligible and name the live-newest lure target.
func TestYankLure_FiresHigh_ArrayrefShape(t *testing.T) {
	g, id := cargoNodeGraph("arrayref", "0.3.9") // victim pinned to the last good, now-yanked release
	h := yankHistory("arrayref",
		yankRel{"0.3.5", true}, yankRel{"0.3.6", true}, yankRel{"0.3.7", true},
		yankRel{"0.3.8", true}, yankRel{"0.3.9", true},
		yankRel{"0.3.10", false}, // the live payload
	)
	fs := runYankLure(g, id, h)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.CheckID != "VC-012" {
		t.Errorf("check id = %q", f.CheckID)
	}
	if f.Severity != finding.SevHigh || f.GateClass != finding.GateEligible {
		t.Errorf("severity/gate = %q/%q, want high/gate-eligible (lure shape present)", f.Severity, f.GateClass)
	}
	if !strings.Contains(f.Evidence, "0.3.10") {
		t.Errorf("evidence should name the live-newest lure target 0.3.10: %q", f.Evidence)
	}
}

// Pinned to a single yanked (buggy) release, no mass-yank run beneath the live
// newest: the anchor fires, but stays MEDIUM / advisory — it is a hygiene note,
// not the attack shape.
func TestYankLure_BaseAdvisory_PinnedYankedNoLure(t *testing.T) {
	g, id := cargoNodeGraph("widget", "1.2.3")
	h := yankHistory("widget",
		yankRel{"1.2.1", false}, yankRel{"1.2.2", false},
		yankRel{"1.2.3", true}, // the one buggy release the maintainer pulled
		yankRel{"1.2.4", false},
	)
	fs := runYankLure(g, id, h)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (pinned-to-yanked anchor), got %d", len(fs))
	}
	if fs[0].Severity != finding.SevMedium || fs[0].GateClass != finding.GateAdvisory {
		t.Errorf("severity/gate = %q/%q, want medium/advisory (no lure run)", fs[0].Severity, fs[0].GateClass)
	}
}

// Pinned to a LIVE version — even of a crate that has a lure shape — is out of
// scope for VC-012 (the resolved-graph payload case is VC-002's build.rs job).
func TestYankLure_Quiet_PinnedLive(t *testing.T) {
	g, id := cargoNodeGraph("arrayref", "0.3.10") // pinned to the live newest itself
	h := yankHistory("arrayref",
		yankRel{"0.3.8", true}, yankRel{"0.3.9", true}, yankRel{"0.3.10", false})
	if fs := runYankLure(g, id, h); len(fs) != 0 {
		t.Errorf("pinned to a live version must not fire VC-012, got %d", len(fs))
	}
}

// A single legit yank with no run and the pinned version LIVE: nothing to say.
func TestYankLure_Quiet_LivePinNoYank(t *testing.T) {
	g, id := cargoNodeGraph("widget", "1.2.4")
	h := yankHistory("widget",
		yankRel{"1.2.1", false}, yankRel{"1.2.2", false},
		yankRel{"1.2.3", true}, yankRel{"1.2.4", false})
	if fs := runYankLure(g, id, h); len(fs) != 0 {
		t.Errorf("live pin should not fire, got %d", len(fs))
	}
}

// Scope guard with teeth: yank data is only trustworthy on cargo, where the
// registry supplies it. A non-cargo node whose history carries Yanked=true (which
// no real non-cargo source sets, but a test can) must be ignored — reading an
// always-false flag elsewhere as "live" would be a silent miss dressed as clean.
func TestYankLure_Quiet_NonCargoEcosystem(t *testing.T) {
	g := graph.New()
	id := "pkg:pypi/lure@1.0.0"
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "pypi", Name: "lure", Version: "1.0.0"})
	h := &datasource.ReleaseHistory{Package: "lure", Ecosystem: "pypi", Releases: []datasource.Release{
		{Version: "1.0.0", Yanked: true}, {Version: "1.0.1", Yanked: true}, {Version: "1.0.2", Yanked: false},
	}}
	if fs := runYankLure(g, id, h); len(fs) != 0 {
		t.Errorf("VC-012 must ignore non-cargo ecosystems (yank data untrustworthy there), got %d", len(fs))
	}
}

// No release history: quiet (nothing to evaluate).
func TestYankLure_Quiet_NoHistory(t *testing.T) {
	g, _ := cargoNodeGraph("arrayref", "0.3.9")
	if fs := (YankLure{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("no release history should be quiet, got %d", len(fs))
	}
}

// A fully-yanked (deprecated) crate: the pinned-to-yanked anchor still fires as an
// advisory (you depend on a withdrawn release), but there is no live newest, so no
// lure elevation. This is a deliberate difference from a lure-only rule.
func TestYankLure_BaseAdvisory_AllYanked(t *testing.T) {
	g, id := cargoNodeGraph("dead", "1.0.1")
	h := yankHistory("dead",
		yankRel{"1.0.0", true}, yankRel{"1.0.1", true}, yankRel{"1.0.2", true})
	fs := runYankLure(g, id, h)
	if len(fs) != 1 {
		t.Fatalf("pinned to a yanked version of a fully-yanked crate should fire the base advisory, got %d", len(fs))
	}
	if fs[0].Severity != finding.SevMedium || fs[0].GateClass != finding.GateAdvisory {
		t.Errorf("severity/gate = %q/%q, want medium/advisory (no live newest = no lure)", fs[0].Severity, fs[0].GateClass)
	}
}

// Semver ordering, not lexical: 0.3.10 must rank above 0.3.9 so the lure shape is
// detected (a lexical sort would place 0.3.10 below 0.3.2 and miss it).
func TestYankLure_SemverOrdering(t *testing.T) {
	h := yankHistory("arrayref",
		yankRel{"0.3.2", false}, yankRel{"0.3.9", true}, yankRel{"0.3.10", false})
	// 0.3.2 live, 0.3.9 yanked, 0.3.10 live — run below the live newest is just
	// 0.3.9 (len 1), so NOT a lure (needs >=2). Proves ordering AND the run gate.
	if _, run, ok := yankLureEndState(h); ok {
		t.Errorf("single yanked below newest is not a lure (run=%d), lexical-sort bug would misread this", run)
	}
}
