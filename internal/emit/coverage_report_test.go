package emit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// Decision D-24: the word CLEAN is a claim, and a scan that resolved nothing has
// not earned it.
func TestBannerNeverSaysCleanOnDegradedCoverage(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: "pkg:pypi/redtiger-tools@0.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "redtiger-tools", Version: "0.0.0",
		Attr: map[string]string{
			graph.AttrUnresolved:      "browser-cookie3,keyboard,selenium",
			graph.AttrUnresolvedCount: "33",
		},
	})
	g.Roots = []string{"pkg:pypi/redtiger-tools@0.0.0"}

	res := verdict.Evaluate(g, nil, verdict.Policy{})
	line, _ := verdictLine(res)

	if strings.Contains(strings.ToUpper(line), "CLEAN") {
		t.Errorf("banner claims CLEAN over 33 unresolved dependencies: %q", line)
	}
	if !strings.Contains(line, "INCOMPLETE") {
		t.Errorf("banner must lead with INCOMPLETE, got %q", line)
	}
	if !strings.Contains(line, "33") {
		t.Errorf("banner must state the unresolved count, got %q", line)
	}
}

func TestCoverageSectionRendersInPDF(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: "pkg:pypi/redtiger-tools@0.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "redtiger-tools", Version: "0.0.0",
		Attr: map[string]string{
			graph.AttrUnresolved:      "browser-cookie3,keyboard,selenium",
			graph.AttrUnresolvedCount: "3",
			graph.AttrFlatResolution:  "pypi",
		},
	})
	g.Roots = []string{"pkg:pypi/redtiger-tools@0.0.0"}
	res := verdict.Evaluate(g, nil, verdict.Policy{})

	var buf bytes.Buffer
	if err := (PDF{}).Emit(&buf, g, res, RunInfo{}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"RESOLUTION COVERAGE", "browser-cookie3", "Flat resolution"} {
		if !strings.Contains(out, want) {
			t.Errorf("PDF is missing %q — the gap must reach the artifact, not just the graph", want)
		}
	}
}

// The 60-row cap is only honest if the rows it keeps are the ones that matter.
// Alphabetical order put eighteen @types/d3-* rows ahead of esbuild.
func TestRiskTableRanksActionableRowsFirst(t *testing.T) {
	g := graph.New()
	mk := func(name string, gate finding.GateClass, sev finding.Severity) {
		id := "pkg:npm/" + name + "@1.0.0"
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: name, Version: "1.0.0"})
		g.AddEdge("pkg:npm/root@1.0.0", id, graph.EdgeDependsOn)
		g.Nodes[id].Findings = []finding.Finding{{
			CheckID: "VC-002a", GateClass: gate, Severity: sev, Confidence: 1, NodeID: id, Title: name,
		}}
		g.Nodes[id].Risk = finding.RiskWarned
	}
	g.AddNode(&graph.Node{ID: "pkg:npm/root@1.0.0", Kind: graph.KindPackage, Name: "root", Version: "1.0.0"})
	g.Roots = []string{"pkg:npm/root@1.0.0"}
	// "@types/..." sorts before "esbuild" alphabetically; esbuild is the one a
	// reader needs.
	mk("@types/d3-array", finding.GateAdvisory, finding.SevLow)
	mk("esbuild", finding.GateEligible, finding.SevHigh)

	var buf bytes.Buffer
	res := verdict.Result{Coverage: g.Coverage(), Risk: map[string]finding.RiskState{}}
	if err := (PDF{}).Emit(&buf, g, res, RunInfo{}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()
	iEsbuild, iTypes := strings.Index(out, "esbuild"), strings.Index(out, "@types/d3-array")
	if iEsbuild < 0 || iTypes < 0 {
		t.Fatalf("both packages should render (esbuild=%d types=%d)", iEsbuild, iTypes)
	}
	if iEsbuild > iTypes {
		t.Error("gate-eligible esbuild must outrank an advisory @types row; the cap hides whatever sorts last")
	}
}

// The PDF ranks and caps by Score; a JSON consumer must be able to see it.
func TestFindingJSONCarriesScore(t *testing.T) {
	f := finding.Finding{
		CheckID: "VC-005", Axis: finding.AxisWeather, Severity: finding.SevMedium,
		GateClass: finding.GateAdvisory, Confidence: 0.35, RecencyDecay: 0.4,
		NodeID: "pkg:npm/x@1.0.0", Title: "burst",
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	score, ok := got["score"].(float64)
	if !ok {
		t.Fatalf("score absent from JSON: %s", raw)
	}
	if want := f.Score(); score != want {
		t.Errorf("score = %v, want %v", score, want)
	}
	if got["check_id"] != "VC-005" {
		t.Errorf("custom marshaller dropped fields: %s", raw)
	}
}

// The EPSS enrichment summary (and any data-source Note) must reach the JSON
// coverage output, so a consumer that never reads the PDF still sees it.
func TestJSONCarriesDataSourceNote(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/x@1.0.0", Kind: graph.KindPackage, Name: "x", Version: "1.0.0"})
	g.MarkRoot("pkg:npm/x@1.0.0")
	res := verdict.Evaluate(g, nil, verdict.Policy{})
	info := RunInfo{DataSources: []DataSourceCoverage{{
		Name:  "epss",
		Stats: datasource.Stats{Queried: 10, FromNet: 8, Gaps: 2},
		Note:  "scored 8 of 10 CVE(s); enriched 6 vulnerable coordinate(s); resolved 4 advisory alias(es) to CVE via OSV /v1/query",
	}}}
	var b bytes.Buffer
	if err := (JSON{}).Emit(&b, g, res, info); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		DataSources []struct {
			Name  string `json:"name"`
			Note  string `json:"note"`
			Stats struct {
				Queried int `json:"queried"`
				Gaps    int `json:"gaps"`
			} `json:"stats"`
		} `json:"data_sources"`
	}
	if err := json.Unmarshal(b.Bytes(), &parsed); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, b.String())
	}
	if len(parsed.DataSources) != 1 {
		t.Fatalf("want 1 data source, got %d", len(parsed.DataSources))
	}
	ds := parsed.DataSources[0]
	if ds.Name != "epss" || !strings.Contains(ds.Note, "enriched 6 vulnerable") {
		t.Errorf("EPSS note missing from JSON coverage: %+v", ds)
	}
	if ds.Stats.Queried != 10 || ds.Stats.Gaps != 2 {
		t.Errorf("EPSS stats missing from JSON coverage: %+v", ds.Stats)
	}
}
