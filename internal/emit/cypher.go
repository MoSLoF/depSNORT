package emit

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// Cypher emits a Neo4j load script. Per Decision D-07 the graph database is an
// OUTPUT TARGET, never a runtime dependency: this writes plain text you pipe
// into cypher-shell, so the scanner stays a standalone static binary.
//
//	depsnort scan -format cypher . > load.cypher
//	cypher-shell -u neo4j -p … -f load.cypher
type Cypher struct{}

// Name implements Emitter.
func (Cypher) Name() string { return "cypher" }

// cypherLabel maps a node kind to a Neo4j label.
func cypherLabel(k graph.NodeKind) string {
	switch k {
	case graph.KindInstallHook:
		return "InstallHook"
	case graph.KindReferencedArtifact:
		return "ReferencedArtifact"
	case graph.KindSink:
		return "Sink"
	default:
		return "Package"
	}
}

// cypherRel maps an edge type to a relationship type.
func cypherRel(t graph.EdgeType) string {
	switch t {
	case graph.EdgeDeclaresHook:
		return "DECLARES_HOOK"
	case graph.EdgeHookExecs:
		return "HOOK_EXECS"
	case graph.EdgeHookFetches:
		return "HOOK_FETCHES"
	case graph.EdgeHookReadsEnv:
		return "HOOK_READS_ENV"
	case graph.EdgeExfil:
		return "EXFIL"
	case graph.EdgeRepublish:
		return "REPUBLISH"
	case graph.EdgeBuildBackend:
		return "BUILD_BACKEND"
	default:
		return "DEPENDS_ON"
	}
}

// cq quotes a string as a Cypher single-quoted literal.
func cq(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

// Emit implements Emitter.
func (Cypher) Emit(w io.Writer, g *graph.Graph, res verdict.Result, info RunInfo) error {
	var b strings.Builder

	b.WriteString("// depSNORT graph load script\n")
	b.WriteString(fmt.Sprintf("// nodes=%d edges=%d exit=%d block=%d gate-eligible=%d advisory=%d\n\n",
		g.Len(), len(g.Edges), res.ExitCode, res.Counts.Block, res.Counts.Eligible, res.Counts.Advisory))

	b.WriteString("// Uniqueness so re-loading a scan updates in place rather than duplicating.\n")
	for _, lbl := range []string{"Package", "InstallHook", "ReferencedArtifact", "Sink"} {
		b.WriteString(fmt.Sprintf(
			"CREATE CONSTRAINT depsnort_%s_id IF NOT EXISTS FOR (n:%s) REQUIRE n.id IS UNIQUE;\n",
			strings.ToLower(lbl), lbl))
	}
	b.WriteString("\n")

	// Nodes.
	for _, n := range g.SortedNodes() {
		b.WriteString(fmt.Sprintf("MERGE (n:%s {id: %s})\n", cypherLabel(n.Kind), cq(n.ID)))
		sets := []string{
			"n.name = " + cq(n.Name),
			"n.risk = " + cq(string(n.Risk)),
			"n.kind = " + cq(string(n.Kind)),
			fmt.Sprintf("n.depth = %d", n.Depth),
			fmt.Sprintf("n.direct = %t", n.Direct),
		}
		if n.Version != "" {
			sets = append(sets, "n.version = "+cq(n.Version))
		}
		if n.Ecosystem != "" {
			sets = append(sets, "n.ecosystem = "+cq(n.Ecosystem))
		}
		// Capability facts become first-class properties for querying.
		// Keys are sorted for deterministic output (Decision D-09).
		var capKeys []string
		for k, v := range n.Attr {
			if strings.HasPrefix(k, "cap.") && v == "true" {
				capKeys = append(capKeys, k)
			}
		}
		sort.Strings(capKeys)
		for _, k := range capKeys {
			sets = append(sets, fmt.Sprintf("n.`%s` = true", k))
		}
		b.WriteString("SET " + strings.Join(sets, ", ") + ";\n")
	}
	b.WriteString("\n")

	// Findings attached to their subject nodes.
	for i, f := range res.Findings {
		b.WriteString(fmt.Sprintf("MATCH (n {id: %s})\n", cq(f.NodeID)))
		b.WriteString(fmt.Sprintf("MERGE (f:Finding {id: %s})\n", cq(fmt.Sprintf("%s#%d", f.CheckID, i))))
		b.WriteString(fmt.Sprintf("SET f.check = %s, f.axis = %s, f.severity = %s, f.gate_class = %s, f.confidence = %g, f.title = %s\n",
			cq(f.CheckID), cq(string(f.Axis)), cq(string(f.Severity)), cq(string(f.GateClass)), f.Confidence, cq(f.Title)))
		b.WriteString("MERGE (n)-[:HAS_FINDING]->(f);\n")
	}
	if len(res.Findings) > 0 {
		b.WriteString("\n")
	}

	// Relationships.
	for _, e := range g.SortedEdges() {
		b.WriteString(fmt.Sprintf("MATCH (a {id: %s}), (b {id: %s}) MERGE (a)-[:%s]->(b);\n",
			cq(e.From), cq(e.To), cypherRel(e.Type)))
	}

	_, err := io.WriteString(w, b.String())
	return err
}
