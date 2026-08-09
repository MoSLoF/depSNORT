package main

import (
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

const wsRoot = "testdata/workspace"

func TestDiscoverFindsEveryProject(t *testing.T) {
	adapters := adapterRegistry(true)
	found, err := discoverProjects(wsRoot, adapters)
	if err != nil {
		t.Fatalf("discoverProjects: %v", err)
	}
	if len(found) != 8 {
		var paths []string
		for _, f := range found {
			paths = append(paths, f.Path)
		}
		t.Fatalf("found %d projects, want 8: %v", len(found), paths)
	}

	byPath := map[string]string{}
	for _, f := range found {
		byPath[filepath.ToSlash(f.Path)] = f.Adapter.Name()
	}
	want := map[string]string{
		wsRoot + "/repo-a":           "npm",
		wsRoot + "/repo-b":           "npm",
		wsRoot + "/py-repo":          "pypi",
		wsRoot + "/nested/deep-repo": "npm",
		wsRoot + "/ruby-repo":        "gem",
		wsRoot + "/rust-repo":        "cargo",
		wsRoot + "/php-repo":         "composer",
		wsRoot + "/dotnet-repo":      "nuget",
	}
	for p, eco := range want {
		if got, ok := byPath[p]; !ok {
			t.Errorf("missing project %s", p)
		} else if got != eco {
			t.Errorf("%s claimed by %q, want %q", p, got, eco)
		}
	}
}

// The decoy lockfile inside node_modules must never be discovered. Walking
// node_modules would resolve vendored copies as first-class projects and, on a
// real workspace, take effectively forever.
func TestDiscoverSkipsNodeModules(t *testing.T) {
	adapters := adapterRegistry(true)
	found, err := discoverProjects(wsRoot, adapters)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if strings.Contains(filepath.ToSlash(f.Path), "node_modules") {
			t.Errorf("discovery descended into node_modules: %s", f.Path)
		}
	}
}

func TestDiscoverIsDeterministic(t *testing.T) {
	adapters := adapterRegistry(true)
	var first []string
	for i := 0; i < 6; i++ {
		found, err := discoverProjects(wsRoot, adapters)
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, f := range found {
			paths = append(paths, f.Path)
		}
		if i == 0 {
			first = paths
			continue
		}
		for j := range paths {
			if paths[j] != first[j] {
				t.Fatalf("run %d differs at %d: %s vs %s", i, j, paths[j], first[j])
			}
		}
	}
}

// The point of merging into one graph: a package at the same version in two
// repos is ONE node, and both repos appear as roots.
func TestMergeDedupesSharedDependencies(t *testing.T) {
	adapters := adapterRegistry(true)
	found, err := discoverProjects(wsRoot, adapters)
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	for _, p := range found {
		sub, err := p.Adapter.Resolve(p.Path)
		if err != nil {
			t.Fatalf("resolve %s: %v", p.Path, err)
		}
		g.Merge(sub)
	}

	if len(g.Roots) != 8 {
		t.Errorf("roots = %d, want 8 (one per project)", len(g.Roots))
	}
	// shared-dep@1.0.0 appears in repo-a and repo-b but must be a single node.
	shared := g.Get("pkg:npm/shared-dep@1.0.0")
	if shared == nil {
		t.Fatal("shared-dep node missing after merge")
	}
	var count int
	for _, n := range g.SortedNodes() {
		if n.Name == "shared-dep" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("shared-dep appears as %d nodes, want 1 (dedupe failed)", count)
	}
	// Both repos must have an edge into it — that is the blast radius.
	var inbound int
	for _, e := range g.SortedEdges() {
		if e.To == shared.ID && e.Type == graph.EdgeDependsOn {
			inbound++
		}
	}
	if inbound != 2 {
		t.Errorf("shared-dep inbound edges = %d, want 2 (one per repo)", inbound)
	}
	// The decoy inside node_modules must not have contributed anything.
	for _, n := range g.SortedNodes() {
		if strings.Contains(n.Name, "DECOY") || strings.Contains(n.Name, "decoy") {
			t.Errorf("decoy node leaked into the graph: %s", n.ID)
		}
	}
}

func TestMergeIsIdempotent(t *testing.T) {
	adapters := adapterRegistry(true)
	found, _ := discoverProjects(wsRoot, adapters)
	g := graph.New()
	for i := 0; i < 2; i++ { // merge everything twice
		for _, p := range found {
			sub, err := p.Adapter.Resolve(p.Path)
			if err != nil {
				t.Fatal(err)
			}
			g.Merge(sub)
		}
	}
	if len(g.Roots) != 8 {
		t.Errorf("roots = %d after double merge, want 8", len(g.Roots))
	}
	for _, n := range g.SortedNodes() {
		if n.Name == "shared-dep" {
			// still one node
			continue
		}
	}
	var edges int
	for _, e := range g.SortedEdges() {
		if e.To == "pkg:npm/shared-dep@1.0.0" {
			edges++
		}
	}
	if edges != 2 {
		t.Errorf("double merge duplicated edges: %d, want 2", edges)
	}
}
