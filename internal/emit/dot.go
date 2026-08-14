package emit

import (
	"fmt"
	"io"
	"strings"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// DOT renders the graph in Graphviz DOT. The styling mirrors the dual-tree
// figure: the declared subgraph reads cool, the install-time subgraph reads hot,
// and risk state drives node color. Render with:
//
//	depsnort scan -format dot . | dot -Tsvg -o tree.svg
type DOT struct{}

// Name implements Emitter.
func (DOT) Name() string { return "dot" }

// palette per risk state: fill, stroke, text.
func riskColors(r finding.RiskState) (string, string, string) {
	switch r {
	case finding.RiskFlagged:
		return "#3b0d1e", "#ff3d71", "#ffd9e3"
	case finding.RiskWarned:
		return "#33280a", "#fbbf24", "#ffeab0"
	default:
		return "#0f2436", "#38bdf8", "#d6f0ff"
	}
}

func nodeShape(k graph.NodeKind) string {
	switch k {
	case graph.KindInstallHook:
		return "box"
	case graph.KindReferencedArtifact:
		return "note"
	case graph.KindSink:
		return "cylinder"
	default:
		return "box"
	}
}

// edgeStyle returns color, style, penwidth for an edge type.
func edgeStyle(t graph.EdgeType) (string, string, string) {
	switch t {
	case graph.EdgeDependsOn:
		return "#7d8fb3", "solid", "1.1"
	case graph.EdgeDeclaresHook:
		return "#ff3d71", "solid", "2.0"
	case graph.EdgeHookExecs:
		return "#ff3d71", "solid", "1.5"
	case graph.EdgeHookFetches:
		return "#fbbf24", "solid", "1.5"
	case graph.EdgeHookReadsEnv:
		return "#fbbf24", "solid", "1.5"
	case graph.EdgeExfil:
		return "#ff3d71", "dashed", "1.6"
	case graph.EdgeRepublish:
		return "#ff3d71", "dashed", "1.6"
	case graph.EdgeBuildBackend:
		return "#c084fc", "dashed", "1.3"
	default:
		return "#7d8fb3", "solid", "1.0"
	}
}

func dotEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// dotLabel builds a readable two-line label for a node.
func dotLabel(n *graph.Node) string {
	switch n.Kind {
	case graph.KindPackage:
		if n.Version != "" {
			return dotEscape(n.Name) + `\n` + dotEscape(n.Version)
		}
		return dotEscape(n.Name)
	case graph.KindInstallHook:
		return `⚙ ` + dotEscape(n.Name)
	case graph.KindReferencedArtifact:
		name := n.Name
		if len(name) > 46 {
			name = name[:43] + "…"
		}
		return dotEscape(name)
	case graph.KindSink:
		return `🔑 ` + dotEscape(n.Name)
	}
	return dotEscape(n.Name)
}

// Emit implements Emitter.
func (DOT) Emit(w io.Writer, g *graph.Graph, res verdict.Result, info RunInfo) error {
	var b strings.Builder
	b.WriteString("digraph depSNORT {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString(`  bgcolor="#080d1a";` + "\n")
	b.WriteString(`  node [style="filled,rounded", fontname="Helvetica", fontsize=11, penwidth=1.6];` + "\n")
	b.WriteString(`  edge [fontname="Helvetica", fontsize=9];` + "\n")
	b.WriteString(fmt.Sprintf("  label=\"depSNORT — %d nodes, %d edges · block=%d gate-eligible=%d advisory=%d · exit %d\";\n",
		g.Len(), len(g.Edges), res.Counts.Block, res.Counts.Eligible, res.Counts.Advisory, res.ExitCode))
	b.WriteString(`  labelloc="t"; fontcolor="#c8d4ec"; fontname="Helvetica"; fontsize=13;` + "\n\n")

	for _, n := range g.SortedNodes() {
		fill, stroke, text := riskColors(n.Risk)
		b.WriteString(fmt.Sprintf(
			"  %q [label=\"%s\", shape=%s, fillcolor=\"%s\", color=\"%s\", fontcolor=\"%s\"];\n",
			n.ID, dotLabel(n), nodeShape(n.Kind), fill, stroke, text))
	}
	b.WriteString("\n")

	for _, e := range g.SortedEdges() {
		color, style, pen := edgeStyle(e.Type)
		label := ""
		if e.Type != graph.EdgeDependsOn {
			label = fmt.Sprintf(", label=%q, fontcolor=%q", string(e.Type), color)
		}
		b.WriteString(fmt.Sprintf("  %q -> %q [color=%q, style=%s, penwidth=%s%s];\n",
			e.From, e.To, color, style, pen, label))
	}
	b.WriteString("}\n")

	_, err := io.WriteString(w, b.String())
	return err
}
