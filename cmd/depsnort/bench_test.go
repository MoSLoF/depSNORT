package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/emit"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
	"ihbv.io/depsnort/internal/verdict"
)

// End-to-end pipeline baselines (D-33): check pipeline -> verdict -> emitters,
// over a synthetic graph the size of a real monorepo scan. These are the numbers
// a future change is measured against; without a recorded baseline, "is this
// slower?" has no answer.

// benchGraph builds a graph of n packages with a realistic shape: a fraction
// carry install hooks with capabilities, and hooks hang artifacts and sinks off
// themselves so risk propagation has something to walk.
func benchGraph(n int) *graph.Graph {
	g := graph.New()
	rootID := purl.NewNpm("bench", "1.0.0").String()
	g.AddNode(&graph.Node{ID: rootID, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "bench", Version: "1.0.0", Attr: map[string]string{"npm.path": "."}})
	g.MarkRoot(rootID)

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("dep%d", i)
		id := purl.NewNpm(name, fmt.Sprintf("1.0.%d", i%50)).String()
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
			Name: name, Version: fmt.Sprintf("1.0.%d", i%50), Depth: 1 + i%6,
			Attr: map[string]string{"npm.path": "node_modules/" + name}})
		g.AddEdge(rootID, id, graph.EdgeDependsOn)

		// ~1 in 17 packages declares an install hook, matching the rough
		// real-world density of hasInstallScript in a large tree.
		if i%17 != 0 {
			continue
		}
		hookID := "hook:" + id + "#postinstall"
		g.AddNode(&graph.Node{ID: hookID, Kind: graph.KindInstallHook, Ecosystem: "npm",
			Name: "postinstall", Attr: map[string]string{
				"hook.package": id, "hook.command": "node install.js",
				"cap.network": "true", "cap.exec": "true",
			}})
		g.AddEdge(id, hookID, graph.EdgeDeclaresHook)

		artID := "artifact:" + id + "#https://cdn.example/bin"
		g.AddNode(&graph.Node{ID: artID, Kind: graph.KindReferencedArtifact, Ecosystem: "npm",
			Name: "https://cdn.example/bin", Attr: map[string]string{
				"artifact.remote": "true", "hook.package": id, "cap.network": "true",
			}})
		g.AddEdge(hookID, artID, graph.EdgeHookFetches)

		if i%51 == 0 {
			sinkID := "sink:" + id + "#NPM_TOKEN"
			g.AddNode(&graph.Node{ID: sinkID, Kind: graph.KindSink, Ecosystem: "npm",
				Name: "NPM_TOKEN", Attr: map[string]string{"hook.package": id}})
			g.AddEdge(hookID, sinkID, graph.EdgeHookReadsEnv)
			g.Get(hookID).Attr["cap.credentials"] = "true"
		}
	}
	return g
}

func benchCtx(g *graph.Graph) *check.Context {
	return &check.Context{Graph: g, Now: time.Unix(1765000000, 0), Config: check.Config{
		InternalScopes: []string{"@internal"},
	}}
}

// The full 13-check pack, offline (no OSV/registry data), which is the pure
// compute cost of judgment.
func benchChecks(b *testing.B, n int) {
	g := benchGraph(n)
	reg := checkRegistry()
	ctx := benchCtx(g)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = reg.RunAll(ctx)
	}
}

func BenchmarkCheckPipeline100(b *testing.B)  { benchChecks(b, 100) }
func BenchmarkCheckPipeline1000(b *testing.B) { benchChecks(b, 1000) }
func BenchmarkCheckPipeline5000(b *testing.B) { benchChecks(b, 5000) }

// Verdict includes risk propagation across the install-time subgraph, which is a
// breadth-first walk per non-clean package — the part most likely to degrade
// non-linearly.
func BenchmarkVerdict1000(b *testing.B) {
	g := benchGraph(1000)
	findings := checkRegistry().RunAll(benchCtx(g))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verdict.Evaluate(g, findings, verdict.Policy{FailOnEligible: true})
	}
}

func benchEmit(b *testing.B, format string, n int) {
	g := benchGraph(n)
	findings := checkRegistry().RunAll(benchCtx(g))
	res := verdict.Evaluate(g, findings, verdict.Policy{})
	em := emit.ByName(format)
	if em == nil {
		b.Fatalf("no emitter %q", format)
	}
	var info emit.RunInfo
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := em.Emit(&buf, g, res, info); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEmitJSON1000(b *testing.B)  { benchEmit(b, "json", 1000) }
func BenchmarkEmitSARIF1000(b *testing.B) { benchEmit(b, "sarif", 1000) }

// The PDF writer is in-tree (no third-party library, D-10), so its cost is ours
// to own and worth a standing baseline.
func BenchmarkEmitPDF1000(b *testing.B) { benchEmit(b, "pdf", 1000) }

// Whole pipeline: checks -> verdict -> JSON, the shape of one `depsnort scan`
// once the graph is in memory.
func BenchmarkScanPipeline1000(b *testing.B) {
	g := benchGraph(1000)
	reg := checkRegistry()
	em := emit.ByName("json")
	var info emit.RunInfo
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := reg.RunAll(benchCtx(g))
		res := verdict.Evaluate(g, findings, verdict.Policy{})
		var buf bytes.Buffer
		if err := em.Emit(&buf, g, res, info); err != nil {
			b.Fatal(err)
		}
	}
}
