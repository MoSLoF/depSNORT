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
	if _, run, ok := h.YankLureShape(); ok {
		t.Errorf("single yanked below newest is not a lure (run=%d), lexical-sort bug would misread this", run)
	}
}

// setNodeAttr sets an attribute on the single node of a cargoNodeGraph, mimicking
// what the enrichYankLure orchestration stage writes.
func setNodeAttr(g *graph.Graph, id, k, v string) {
	n := g.Get(id)
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	n.Attr[k] = v
}

// Increment 2: the full arrayref signature. Yank-lure shape PLUS the live-newest
// introduces a build-dep that is a typosquat of a popular crate (proc-macro1 vs
// proc-macro2) => CRITICAL, and the evidence names the impersonated crate.
func TestYankLure_Critical_TyposquatBuildDep(t *testing.T) {
	g, id := cargoNodeGraph("arrayref", "0.3.9")
	setNodeAttr(g, id, "yanklure.introduced_build_deps", "proc-macro1")
	h := yankHistory("arrayref",
		yankRel{"0.3.7", true}, yankRel{"0.3.8", true}, yankRel{"0.3.9", true},
		yankRel{"0.3.10", false})
	fs := runYankLure(g, id, h)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != finding.SevCritical {
		t.Errorf("severity = %q, want critical (typosquatted introduced build-dep)", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Evidence, "proc-macro1") || !strings.Contains(fs[0].Evidence, "proc-macro2") {
		t.Errorf("evidence should name proc-macro1~proc-macro2: %q", fs[0].Evidence)
	}
}

// A legit new build-dep (cc — a popular crate, not a typosquat) added by the
// live-newest keeps the finding at HIGH (the lure shape's level), not critical.
// This is the sketch's hard negative: "new build-dep" alone is not the attack.
func TestYankLure_High_LegitNewBuildDep(t *testing.T) {
	g, id := cargoNodeGraph("widget", "0.4.8")
	setNodeAttr(g, id, "yanklure.introduced_build_deps", "cc")
	h := yankHistory("widget",
		yankRel{"0.4.6", true}, yankRel{"0.4.7", true}, yankRel{"0.4.8", true},
		yankRel{"0.5.0", false})
	fs := runYankLure(g, id, h)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != finding.SevHigh {
		t.Errorf("severity = %q, want high (a legit popular build-dep is not a typosquat)", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Evidence, "cc") {
		t.Errorf("evidence should still note the introduced build-dep cc: %q", fs[0].Evidence)
	}
}

// Lure shape with no enrichment attribute (offline, or no introduced build-dep):
// Increment-1 behavior is unchanged — high, not critical.
func TestYankLure_High_NoIntroducedDeps(t *testing.T) {
	g, id := cargoNodeGraph("arrayref", "0.3.9")
	h := yankHistory("arrayref",
		yankRel{"0.3.8", true}, yankRel{"0.3.9", true}, yankRel{"0.3.10", false})
	fs := runYankLure(g, id, h)
	if len(fs) != 1 || fs[0].Severity != finding.SevHigh {
		t.Fatalf("want 1 high finding without enrichment, got %d (sev %v)", len(fs), func() finding.Severity {
			if len(fs) > 0 {
				return fs[0].Severity
			}
			return ""
		}())
	}
}

// The typosquat neighbour helper: distance-1 near-misses hit, exact members and
// distant names miss.
func TestCargoTyposquatNeighbor(t *testing.T) {
	if orig, ok := cargoTyposquatNeighbor("proc-macro1"); !ok || orig != "proc-macro2" {
		t.Errorf("proc-macro1 => (%q,%v), want (proc-macro2,true)", orig, ok)
	}
	if _, ok := cargoTyposquatNeighbor("proc-macro2"); ok {
		t.Error("proc-macro2 IS the popular crate, must not be its own typosquat")
	}
	if _, ok := cargoTyposquatNeighbor("totally-unrelated-crate"); ok {
		t.Error("a distant name must not be flagged")
	}
}
