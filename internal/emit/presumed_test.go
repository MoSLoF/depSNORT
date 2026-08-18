package emit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// presumedGraph: an observed root, a presumed transitive node with a finding,
// and a contested node — the three version-truth states an emitter must
// distinguish (D-44).
func presumedGraph() (*graph.Graph, verdict.Result) {
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/app@1.0.0", Kind: graph.KindPackage, Name: "app", Version: "1.0.0", Ecosystem: "pypi"})
	g.MarkRoot(root.ID)
	pres := g.AddNode(&graph.Node{ID: "pkg:pypi/leftpad@2.0.0", Kind: graph.KindPackage, Name: "leftpad", Version: "2.0.0", Ecosystem: "pypi", Depth: 2,
		Attr: map[string]string{graph.AttrVersionTruth: graph.TruthPresumed, graph.AttrVersionCandidates: "3"}})
	cont := g.AddNode(&graph.Node{ID: "pkg:pypi/split", Kind: graph.KindPackage, Name: "split", Ecosystem: "pypi", Depth: 2,
		Attr: map[string]string{graph.AttrVersionTruth: graph.TruthContested}})
	g.AddEdge(root.ID, pres.ID, graph.EdgeDependsOn)
	g.AddEdge(root.ID, cont.ID, graph.EdgeDependsOn)

	res := verdict.Evaluate(g, []finding.Finding{{
		CheckID: "VC-006", Axis: finding.AxisKnownCompromise, Severity: finding.SevHigh,
		GateClass: finding.GateBlock, Confidence: 0.9, NodeID: pres.ID,
		Title: "typosquat of left-pad", Evidence: "edit distance 1",
	}}, verdict.Policy{})
	return g, res
}

func TestJSONSurfacesVersionTruth(t *testing.T) {
	g, res := presumedGraph()
	var buf bytes.Buffer
	if err := (JSON{}).Emit(&buf, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Nodes []struct {
			ID           string `json:"id"`
			VersionTruth string `json:"version_truth"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, n := range doc.Nodes {
		got[n.ID] = n.VersionTruth
	}
	if got["pkg:pypi/leftpad@2.0.0"] != graph.TruthPresumed {
		t.Errorf("presumed node version_truth = %q, want presumed", got["pkg:pypi/leftpad@2.0.0"])
	}
	if got["pkg:pypi/split"] != graph.TruthContested {
		t.Errorf("contested node version_truth = %q, want contested", got["pkg:pypi/split"])
	}
	// An observed node OMITS the field, so its absence is meaningful.
	if got["pkg:pypi/app@1.0.0"] != "" {
		t.Errorf("observed node should omit version_truth, got %q", got["pkg:pypi/app@1.0.0"])
	}
}

func TestSARIFMarksPresumedFindings(t *testing.T) {
	g, res := presumedGraph()
	var buf bytes.Buffer
	if err := (SARIF{}).Emit(&buf, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "versionTruth") || !strings.Contains(out, "presumedVersion") {
		t.Error("SARIF finding on a presumed node did not carry the version-truth properties")
	}
}

func TestDOTStylesPresumedNodes(t *testing.T) {
	g, res := presumedGraph()
	var buf bytes.Buffer
	if err := (DOT{}).Emit(&buf, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "(presumed)") {
		t.Error("DOT did not label the presumed node")
	}
	if !strings.Contains(out, "dashed") {
		t.Error("DOT did not give presumed/contested nodes a dashed outline")
	}
	if !strings.Contains(out, "(contested)") {
		t.Error("DOT did not label the contested node")
	}
}

func TestPDFRendersWithPresumedMarkers(t *testing.T) {
	g, res := presumedGraph()
	var buf bytes.Buffer
	// The PDF is binary; this asserts it renders without error over a graph
	// carrying presumed and contested nodes (the marker logic runs).
	if err := (PDF{}).Emit(&buf, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Error("empty PDF")
	}
}

func TestCypherCarriesVersionTruth(t *testing.T) {
	g, res := presumedGraph()
	var b bytes.Buffer
	if err := (Cypher{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "n.version_truth = 'presumed'") {
		t.Error("cypher did not promote version_truth to a queryable property")
	}
}
