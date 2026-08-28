// Package instsurf materializes an install-surface Surface (hooks, referenced
// artifacts, credential sinks) into the dependency graph.
//
// It exists to stop the newer adapters (cargo, rubygems, nuget) from each
// copy-pasting the ~60-line graph-wiring block that npm, pypi and composer
// carry inline. Those three predate this helper and keep their own copies;
// everything added after D-26 wires through here.
//
// Extraction vs judgment (Decision D-03): this writes FACTS — capability
// attributes and edges — and never sets risk state. The VC-002 family judges.
package instsurf

import (
	"os"
	"path/filepath"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

// ProjectDir resolves a project root from a path that may be a directory or the
// lockfile itself.
func ProjectDir(path string) string {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return filepath.Dir(path)
	}
	return path
}

// AddToGraph materializes s as install-time nodes and edges hanging off pkg.
func AddToGraph(g *graph.Graph, pkg *graph.Node, s installsurface.Surface) {
	for _, h := range s.Hooks {
		hookID := "hook:" + pkg.ID + "#" + sanitize(h.Name)
		hn := g.AddNode(&graph.Node{
			ID:        hookID,
			Kind:      graph.KindInstallHook,
			Ecosystem: pkg.Ecosystem,
			Name:      h.Name,
			Depth:     pkg.Depth,
			Attr: map[string]string{
				"hook.command": truncate(h.Command, 400),
				"hook.package": pkg.ID,
			},
		})
		setCaps(hn, h.Caps)
		if len(h.Evidence) > 0 {
			hn.Attr["hook.evidence"] = strings.Join(h.Evidence, ",")
		}
		g.AddEdge(pkg.ID, hookID, graph.EdgeDeclaresHook)

		// The worm loop, finally drawn (D-152). graph.EdgeRepublish has been
		// defined as "worm loop back into the declared tree", counted in the
		// verdict's install-time subgraph and rendered by the Cypher/DOT
		// emitters since the graph vocabulary was written — but no detector ever
		// created one, so the edge type was aspirational. A hook that publishes
		// points back at its own package: that IS the loop, and it is what makes
		// the worm chain visible in a graph view rather than only in a finding.
		//
		// HasCap folds in the hook's artifacts, which is required rather than
		// incidental: the real attack puts an unremarkable `node ./harvest.js`
		// in the hook command and the publish inside the referenced script.
		// Testing h.Caps alone drew the edge only for a publish inlined into the
		// command — the one form Shai-Hulud does not use. VC-002k already
		// reasons over the absorbed surface (collectHooks folds artifact caps
		// into the hook view); the edge has to agree with the finding, or the
		// graph contradicts the report.
		if h.HasCap(installsurface.CapPropagate) {
			g.AddEdge(hookID, pkg.ID, graph.EdgeRepublish)
		}

		// The exfil channel, drawn (the VC-002d signature made visible in the
		// graph). graph.EdgeExfil was defined as "artifact/sink -> C2", counted
		// in the install-time subgraph and rendered by the emitters, but like
		// EdgeRepublish before D-152 no detector ever produced one. A hook that
		// combines named-credential access with network egress is exfil-capable
		// (exactly VC-002d's condition, HasCap folding artifact caps in the same
		// way): the edge links each credential sink to each remote destination
		// the hook can reach, so the leak is legible in a graph view and not only
		// in the finding. Both endpoints already sit in the install-time subgraph
		// (hook->sink, hook->fetch), so this draws no risk propagation the
		// existing edges did not.
		if h.HasCap(installsurface.CapCredentials) && h.HasCap(installsurface.CapNetwork) {
			for _, sk := range h.Sinks {
				sinkID := "sink:" + pkg.ID + "#" + sk.Name
				for _, a := range h.Artifacts {
					if a.Remote {
						g.AddEdge(sinkID, "artifact:"+pkg.ID+"#"+a.Ref, graph.EdgeExfil)
					}
				}
			}
		}

		for _, a := range h.Artifacts {
			artID := "artifact:" + pkg.ID + "#" + a.Ref
			an := g.AddNode(&graph.Node{
				ID:        artID,
				Kind:      graph.KindReferencedArtifact,
				Ecosystem: pkg.Ecosystem,
				Name:      a.Ref,
				Depth:     pkg.Depth,
				Attr: map[string]string{
					"artifact.remote": boolStr(a.Remote),
					"artifact.read":   boolStr(a.Read),
					"hook.package":    pkg.ID,
				},
			})
			setCaps(an, a.Caps)
			if len(a.Evidence) > 0 {
				an.Attr["artifact.evidence"] = strings.Join(a.Evidence, ",")
			}
			if a.Remote {
				g.AddEdge(hookID, artID, graph.EdgeHookFetches)
			} else {
				g.AddEdge(hookID, artID, graph.EdgeHookExecs)
			}
		}

		for _, sk := range h.Sinks {
			sinkID := "sink:" + pkg.ID + "#" + sk.Name
			g.AddNode(&graph.Node{
				ID:        sinkID,
				Kind:      graph.KindSink,
				Ecosystem: pkg.Ecosystem,
				Name:      sk.Name,
				Depth:     pkg.Depth,
				Attr: map[string]string{
					"sink.evidence": sk.Evidence,
					"hook.package":  pkg.ID,
				},
			})
			g.AddEdge(hookID, sinkID, graph.EdgeHookReadsEnv)
		}
	}
}

func setCaps(n *graph.Node, caps []installsurface.Capability) {
	if n.Attr == nil {
		n.Attr = map[string]string{}
	}
	for _, c := range caps {
		n.Attr["cap."+string(c)] = "true"
	}
}

func sanitize(name string) string {
	return strings.ReplaceAll(name, ":", "_")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
