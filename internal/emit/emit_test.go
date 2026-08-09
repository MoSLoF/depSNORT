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

func sampleGraph() (*graph.Graph, verdict.Result) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/evil@1.0.0", Kind: graph.KindPackage, Name: "evil", Version: "1.0.0", Ecosystem: "npm"})
	g.AddNode(&graph.Node{ID: "hook:evil#preinstall", Kind: graph.KindInstallHook, Name: "preinstall",
		Attr: map[string]string{"cap.network": "true", "cap.credentials": "true"}})
	g.MarkRoot("pkg:npm/evil@1.0.0")
	g.AddEdge("pkg:npm/evil@1.0.0", "hook:evil#preinstall", graph.EdgeDeclaresHook)

	res := verdict.Evaluate(g, []finding.Finding{{
		CheckID: "VC-002d", Axis: finding.AxisKnownCompromise, Severity: finding.SevCritical,
		GateClass: finding.GateBlock, Confidence: 0.95, NodeID: "pkg:npm/evil@1.0.0",
		Title: "install hook is exfil-capable", Evidence: "creds + network",
	}}, verdict.Policy{})
	return g, res
}

func TestByNameCoversAllFormats(t *testing.T) {
	for _, f := range Formats() {
		if ByName(f) == nil {
			t.Errorf("ByName(%q) returned nil", f)
		}
	}
	if ByName("xml") != nil {
		t.Error("unknown format should return nil")
	}
}

func TestDOTEmitsStyledGraph(t *testing.T) {
	g, res := sampleGraph()
	var b bytes.Buffer
	if err := (DOT{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"digraph dependaSNORT", "pkg:npm/evil@1.0.0", "declares-hook", "rankdir=LR"} {
		if !strings.Contains(out, want) {
			t.Errorf("DOT output missing %q", want)
		}
	}
	// The flagged package must carry the flagged stroke color.
	if !strings.Contains(out, "#ff3d71") {
		t.Error("DOT output missing flagged color")
	}
}

func TestCypherEmitsLabelsAndRelationships(t *testing.T) {
	g, res := sampleGraph()
	var b bytes.Buffer
	if err := (Cypher{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"MERGE (n:Package {id: 'pkg:npm/evil@1.0.0'})",
		"MERGE (n:InstallHook",
		"DECLARES_HOOK",
		"CREATE CONSTRAINT",
		"HAS_FINDING",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Cypher output missing %q", want)
		}
	}
}

func TestCypherEscapesQuotes(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/it's@1", Kind: graph.KindPackage, Name: "it's"})
	res := verdict.Evaluate(g, nil, verdict.Policy{})
	var b bytes.Buffer
	if err := (Cypher{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `it\'s`) {
		t.Errorf("single quote not escaped: %s", b.String())
	}
}

func TestSARIFIsValidAndMapsGateClassToLevel(t *testing.T) {
	g, res := sampleGraph()
	var b bytes.Buffer
	info := RunInfo{Rules: []RuleInfo{{
		ID: "VC-002d", Axis: "known-compromise", Severity: "critical",
		GateClass: "block", Description: "exfil-capable install hook",
	}}}
	if err := (SARIF{}).Emit(&b, g, res, info); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b.Bytes(), &parsed); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("version = %v", parsed["version"])
	}
	runs := parsed["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	r := results[0].(map[string]any)
	if r["level"] != "error" {
		t.Errorf("block finding level = %v, want error", r["level"])
	}
	if r["ruleId"] != "VC-002d" {
		t.Errorf("ruleId = %v", r["ruleId"])
	}
}

func TestSARIFAdvisoryIsNote(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/x@1", Kind: graph.KindPackage, Name: "x"})
	res := verdict.Evaluate(g, []finding.Finding{{
		CheckID: "VC-006", NodeID: "pkg:npm/x@1", GateClass: finding.GateAdvisory,
		Severity: finding.SevMedium, Confidence: 0.5, Title: "typosquat",
	}}, verdict.Policy{})
	var b bytes.Buffer
	if err := (SARIF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"level": "note"`) {
		t.Error("advisory finding should map to SARIF level note")
	}
}
