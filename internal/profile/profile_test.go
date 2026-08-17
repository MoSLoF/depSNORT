package profile

import (
	"encoding/json"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// pkgGraph builds a one-package graph with the given install surface attached
// through the same helper the adapters use, so the test reads the structure
// production writes rather than a hand-rolled imitation of it.
func pkgGraph(t *testing.T, purlID string, s installsurface.Surface) (*graph.Graph, *graph.Node) {
	t.Helper()
	g := graph.New()
	n := g.AddNode(&graph.Node{
		ID: purlID, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "acme-widget", Version: "1.2.3",
	})
	g.MarkRoot(purlID)
	instsurf.AddToGraph(g, n, s)
	return g, n
}

func TestFromGraphCollectsTheInstallTimeSubgraph(t *testing.T) {
	surface := installsurface.Surface{Hooks: []installsurface.Hook{{
		Name:    "postinstall",
		Command: "node ./scripts/setup.js",
		Caps:    []installsurface.Capability{installsurface.CapExec},
		Artifacts: []installsurface.Artifact{{
			Ref:    "https://cdn.example.invalid/blob.bin?cachebust=99",
			Remote: true,
			Read:   true,
			Caps:   []installsurface.Capability{installsurface.CapNetwork},
		}},
		Sinks: []installsurface.Sink{{Name: "NPM_TOKEN", Evidence: "env.NPM_TOKEN"}},
	}}}

	g, n := pkgGraph(t, "pkg:npm/acme-widget@1.2.3", surface)
	p := FromGraph(g, n)

	if p.Schema != Schema {
		t.Errorf("Schema = %q, want %q", p.Schema, Schema)
	}
	if len(p.Hooks) != 1 || p.Hooks[0] != "postinstall" {
		t.Errorf("Hooks = %v, want [postinstall]", p.Hooks)
	}
	if len(p.Caps) != 2 || p.Caps[0] != "exec" || p.Caps[1] != "network" {
		t.Errorf("Caps = %v, want [exec network] (union over hook and artifact, sorted)", p.Caps)
	}
	// Host, not URL: a cache-busting query string changing between releases is
	// not a security event; a new destination is.
	if len(p.RemoteHosts) != 1 || p.RemoteHosts[0] != "cdn.example.invalid" {
		t.Errorf("RemoteHosts = %v, want [cdn.example.invalid]", p.RemoteHosts)
	}
	if len(p.Sinks) != 1 || p.Sinks[0] != "NPM_TOKEN" {
		t.Errorf("Sinks = %v, want [NPM_TOKEN]", p.Sinks)
	}
}

func TestUnreadArtifactIsRecordedAsUnobserved(t *testing.T) {
	surface := installsurface.Surface{Hooks: []installsurface.Hook{{
		Name:      "postinstall",
		Command:   "node ./scripts/setup.js",
		Artifacts: []installsurface.Artifact{{Ref: "scripts/setup.js", Read: false}},
	}}}
	g, n := pkgGraph(t, "pkg:npm/acme-widget@1.2.3", surface)

	p := FromGraph(g, n)
	if !containsString(p.Unobserved, UnobservedInstallSurface) {
		t.Fatalf("Unobserved = %v, want it to record the unread install surface", p.Unobserved)
	}
	if len(p.Caps) != 0 {
		t.Errorf("Caps = %v; an unread artifact must contribute no capability", p.Caps)
	}
	// The point of the flag: this profile says "no capabilities seen", and a
	// baseline built from it must not be readable as "no capabilities exist".
}

func TestNonRegistrySourceIsUnobserved(t *testing.T) {
	g, n := pkgGraph(t, "pkg:npm/acme-widget@1.2.3", installsurface.Surface{})
	n.SetSource(graph.SourceGit, "git+https://example.invalid/r.git")

	p := FromGraph(g, n)
	if p.SourceClass != graph.SourceGit {
		t.Errorf("SourceClass = %q, want %q", p.SourceClass, graph.SourceGit)
	}
	if !containsString(p.Unobserved, UnobservedSource) {
		t.Errorf("Unobserved = %v, want %q", p.Unobserved, UnobservedSource)
	}
}

func TestTopologyDigestTracksDirectDependencies(t *testing.T) {
	build := func(deps ...string) string {
		g := graph.New()
		root := g.AddNode(&graph.Node{ID: "pkg:npm/app@1.0.0", Kind: graph.KindPackage,
			Ecosystem: "npm", Name: "app", Version: "1.0.0"})
		g.MarkRoot(root.ID)
		for _, d := range deps {
			g.AddNode(&graph.Node{ID: d, Kind: graph.KindPackage, Ecosystem: "npm"})
			g.AddEdge(root.ID, d, graph.EdgeDependsOn)
		}
		return FromGraph(g, root).TopologyDigest
	}

	a := build("pkg:npm/x@1.0.0", "pkg:npm/y@2.0.0")
	reordered := build("pkg:npm/y@2.0.0", "pkg:npm/x@1.0.0")
	changed := build("pkg:npm/x@1.0.0", "pkg:npm/z@3.0.0")

	if a != reordered {
		t.Error("topology digest must not depend on edge insertion order")
	}
	if a == changed {
		t.Error("topology digest must change when a direct dependency changes")
	}
	if build() != "" {
		t.Error("a package with no dependencies must have an empty digest, not a hash of nothing")
	}
}

// TestProfileIsDeterministic is the property a committed baseline depends on:
// re-profiling the same graph must produce identical bytes, or every scan would
// report phantom drift.
func TestProfileIsDeterministic(t *testing.T) {
	surface := installsurface.Surface{Hooks: []installsurface.Hook{{
		Name: "preinstall",
		Caps: []installsurface.Capability{
			installsurface.CapNetwork, installsurface.CapExec, installsurface.CapCredentials,
		},
		Artifacts: []installsurface.Artifact{
			{Ref: "https://b.example.invalid/x", Remote: true, Read: true},
			{Ref: "https://a.example.invalid/y", Remote: true, Read: true},
		},
		Sinks: []installsurface.Sink{{Name: "AWS_SECRET_ACCESS_KEY"}, {Name: "NPM_TOKEN"}},
	}}}

	var first []byte
	for i := range 20 {
		g, n := pkgGraph(t, "pkg:npm/acme-widget@1.2.3", surface)
		raw, err := json.Marshal(FromGraph(g, n))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if i == 0 {
			first = raw
			continue
		}
		if string(raw) != string(first) {
			t.Fatalf("profile is not deterministic:\n run 0: %s\n run %d: %s", first, i, raw)
		}
	}
}

func TestWithPublisherRecordsAbsenceAsUnknown(t *testing.T) {
	g, n := pkgGraph(t, "pkg:npm/acme-widget@1.2.3", installsurface.Surface{})
	base := FromGraph(g, n)

	// No history at all.
	if p := base.WithPublisher(nil); !containsString(p.Unobserved, UnobservedPublisher) {
		t.Errorf("Unobserved = %v, want %q when no history is available", p.Unobserved, UnobservedPublisher)
	}

	// History with no per-version publisher (rubygems, nuget, composer, pypi).
	h := &datasource.ReleaseHistory{Package: "acme-widget", Ecosystem: "npm"}
	if p := base.WithPublisher(h); !p.Publisher.IsZero() ||
		!containsString(p.Unobserved, UnobservedPublisher) {
		t.Errorf("a history with no publishers must record %q, got %v",
			UnobservedPublisher, p.Unobserved)
	}

	// History that does carry one.
	h.Publishers = map[string]datasource.Publisher{
		"1.2.3": {ID: "12345", Name: "acme-bot", Source: "npm._npmUser"},
	}
	p := base.WithPublisher(h)
	if p.Publisher.Key() != "12345" {
		t.Errorf("Publisher.Key() = %q, want 12345", p.Publisher.Key())
	}
	if containsString(p.Unobserved, UnobservedPublisher) {
		t.Error("a known publisher must clear the unobserved marker")
	}
}

// TestWithPublisherDoesNotMutateItsReceiver guards the slice-aliasing trap: a
// Profile is copied by value but its slices share backing arrays.
func TestWithPublisherDoesNotMutateItsReceiver(t *testing.T) {
	g, n := pkgGraph(t, "pkg:npm/acme-widget@1.2.3", installsurface.Surface{})
	n.SetSource(graph.SourceGit, "git+https://example.invalid/r.git")
	base := FromGraph(g, n).WithPublisher(nil)

	before := append([]string(nil), base.Unobserved...)
	_ = base.WithPublisher(&datasource.ReleaseHistory{
		Package:    "acme-widget",
		Publishers: map[string]datasource.Publisher{"1.2.3": {ID: "1", Name: "who"}},
	})
	if len(base.Unobserved) != len(before) {
		t.Fatalf("receiver mutated: %v -> %v", before, base.Unobserved)
	}
	for i := range before {
		if base.Unobserved[i] != before[i] {
			t.Fatalf("receiver mutated: %v -> %v", before, base.Unobserved)
		}
	}
}

func TestFromGraphRejectsNonPackageNodes(t *testing.T) {
	g := graph.New()
	hook := g.AddNode(&graph.Node{ID: "hook:x", Kind: graph.KindInstallHook, Name: "postinstall"})
	if p := FromGraph(g, hook); !p.IsZero() {
		t.Errorf("FromGraph over a hook node returned %+v, want the zero profile", p)
	}
	if p := FromGraph(nil, nil); !p.IsZero() {
		t.Error("FromGraph(nil, nil) must return the zero profile")
	}
}

// TestRemoteArtifactIsNotACoverageGap: depSNORT never fetches what a hook would
// download (D-04), so a remote artifact is unread BY DESIGN. Marking that as
// degraded coverage would make nearly every hook-bearing profile claim to be a
// lower bound, which would make the marker meaningless where it matters.
func TestRemoteArtifactIsNotACoverageGap(t *testing.T) {
	surface := installsurface.Surface{Hooks: []installsurface.Hook{{
		Name:    "postinstall",
		Command: "node ./fetch.js",
		Artifacts: []installsurface.Artifact{
			{Ref: "https://cdn.example.invalid/blob.bin", Remote: true, Read: false},
		},
	}}}
	g, n := pkgGraph(t, "pkg:npm/acme-widget@1.2.3", surface)

	p := FromGraph(g, n)
	if containsString(p.Unobserved, UnobservedInstallSurface) {
		t.Errorf("Unobserved = %v; an unfetched REMOTE artifact is the zero-execution "+
			"model working, not a coverage gap", p.Unobserved)
	}
	if len(p.RemoteHosts) != 1 {
		t.Errorf("RemoteHosts = %v; the destination must still be recorded", p.RemoteHosts)
	}
}
