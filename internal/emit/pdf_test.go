package emit

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

func TestPDFStructureIsValid(t *testing.T) {
	g, res := sampleGraph()
	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := b.Bytes()

	if !bytes.HasPrefix(out, []byte("%PDF-1.4")) {
		t.Error("missing PDF header")
	}
	if !bytes.HasSuffix(bytes.TrimSpace(out), []byte("%%EOF")) {
		t.Error("missing EOF marker")
	}
	for _, want := range []string{"/Type /Catalog", "/Type /Pages", "/Type /Page", "xref", "trailer", "startxref"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("missing %q", want)
		}
	}
	// The xref offsets must actually point at object headers, or readers choke.
	idx := bytes.LastIndex(out, []byte("startxref"))
	if idx < 0 {
		t.Fatal("no startxref")
	}
	var xrefPos int
	if _, err := fmtSscan(string(out[idx+len("startxref"):]), &xrefPos); err != nil {
		t.Fatalf("unparsable startxref: %v", err)
	}
	if xrefPos <= 0 || xrefPos >= len(out) {
		t.Fatalf("startxref offset %d out of range (len %d)", xrefPos, len(out))
	}
	if !bytes.HasPrefix(out[xrefPos:], []byte("xref")) {
		t.Errorf("startxref does not point at the xref table")
	}
}

// fmtSscan is a tiny helper so the test does not import fmt just for one call.
func fmtSscan(s string, out *int) (int, error) {
	s = strings.TrimSpace(s)
	n := 0
	consumed := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
		consumed++
	}
	*out = n
	return consumed, nil
}

func TestPDFIsDeterministic(t *testing.T) {
	g1, res1 := sampleGraph()
	g2, res2 := sampleGraph()
	var a, b bytes.Buffer
	if err := (PDF{}).Emit(&a, g1, res1, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if err := (PDF{}).Emit(&b, g2, res2, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("two renders of identical data differ — the report must carry no timestamp (D-13)")
	}
	if bytes.Contains(a.Bytes(), []byte("/CreationDate")) {
		t.Error("a CreationDate would make output non-reproducible")
	}
}

func TestPDFContainsVerdictAndFinding(t *testing.T) {
	g, res := sampleGraph()
	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// Content streams are uncompressed, so report text is directly searchable.
	for _, want := range []string{"depSNORT", "BLOCKED", "VC-002d", "PACKAGE RISK", "FINDINGS"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestPDFCleanTreeReport(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/ok@1.0.0", Kind: graph.KindPackage, Name: "ok", Version: "1.0.0"})
	g.MarkRoot("pkg:npm/ok@1.0.0")
	res := verdict.Evaluate(g, nil, verdict.Policy{})

	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "CLEAN") {
		t.Error("clean tree should render a CLEAN verdict")
	}
	if !strings.Contains(b.String(), "No findings") {
		t.Error("clean tree should say so explicitly rather than showing an empty section")
	}
}

func TestPDFReportsCoverageGaps(t *testing.T) {
	g, res := sampleGraph()
	info := RunInfo{DataSources: []DataSourceCoverage{{
		Name:  "osv",
		Stats: datasourceStatsWithGaps(3),
	}}}
	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, info); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Coverage is incomplete") {
		t.Error("degraded coverage must be stated in the report, not silently omitted")
	}
}

func TestEscapePDF(t *testing.T) {
	cases := map[string]string{
		`plain`:      `plain`,
		`a(b)c`:      `a\(b\)c`,
		`back\slash`: `back\\slash`,
		"tab\there":  "tab here",
		"em—dash":    "em-dash",
		"quote“x":    `quote"x`,
	}
	for in, want := range cases {
		if got := escapePDF(in); got != want {
			t.Errorf("escapePDF(%q) = %q, want %q", in, got, want)
		}
	}
	// Unmapped non-ASCII must degrade to '?' rather than emit raw bytes that a
	// WinAnsi base-14 font would render as garbage.
	if got := escapePDF("日本"); got != "??" {
		t.Errorf("escapePDF(non-latin) = %q, want %q", got, "??")
	}
}

func TestWrapTextRespectsWidth(t *testing.T) {
	lines := wrapText(strings.Repeat("word ", 60), 9, 200)
	if len(lines) < 2 {
		t.Fatal("long text was not wrapped")
	}
	for _, l := range lines {
		if textWidth(l, 9) > 200.5 {
			t.Errorf("line exceeds width: %q", l)
		}
	}
	// A single unbreakable token must be hard-split, not allowed to overflow.
	long := strings.Repeat("A", 400)
	for _, l := range wrapText(long, 9, 120) {
		if textWidth(l, 9) > 120.5 {
			t.Errorf("over-long token not hard-split: width %.1f", textWidth(l, 9))
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("short", 10); got != "short" {
		t.Errorf("got %q", got)
	}
	if got := truncateRunes("abcdefghijklmnop", 10); len([]rune(got)) != 10 {
		t.Errorf("truncateRunes did not cap length: %q (%d)", got, len([]rune(got)))
	}
}

func TestPDFGateOrdering(t *testing.T) {
	g := graph.New()
	for _, id := range []string{"pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1"} {
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Name: id, Version: "1"})
	}
	res := verdict.Evaluate(g, []finding.Finding{
		{CheckID: "VC-006", NodeID: "pkg:npm/a@1", GateClass: finding.GateAdvisory, Confidence: 1, Title: "advisory item"},
		{CheckID: "VC-001", NodeID: "pkg:npm/b@1", GateClass: finding.GateBlock, Confidence: 1, Title: "block item"},
		{CheckID: "VC-005", NodeID: "pkg:npm/c@1", GateClass: finding.GateEligible, Confidence: 1, Title: "eligible item"},
	}, verdict.Policy{})

	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	iBlock := strings.Index(out, "block item")
	iElig := strings.Index(out, "eligible item")
	iAdv := strings.Index(out, "advisory item")
	if iBlock < 0 || iElig < 0 || iAdv < 0 {
		t.Fatal("not all findings rendered")
	}
	if !(iBlock < iElig && iElig < iAdv) {
		t.Errorf("findings must read block -> gate-eligible -> advisory, got offsets %d/%d/%d", iBlock, iElig, iAdv)
	}
}

// A finding carrying an exploit-prediction score renders EPSS as a first-class,
// de-duplicated line — the score appears once, on its own line (not twice, once
// here and once inside the evidence prose) — and a gate-eligible finding says why
// it was escalated.
func TestPDFRendersEPSSLine(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/hot@1.0.0", Kind: graph.KindPackage, Name: "hot", Version: "1.0.0"})
	g.MarkRoot("pkg:npm/hot@1.0.0")
	res := verdict.Evaluate(g, []finding.Finding{{
		CheckID:    "VC-008",
		Axis:       finding.AxisVuln,
		Severity:   finding.SevMedium,
		GateClass:  finding.GateEligible,
		Confidence: 1,
		NodeID:     "pkg:npm/hot@1.0.0",
		Title:      "1 known vulnerability",
		Evidence:   "hot@1.0.0 is affected by CVE-2021-44228; peak EPSS 0.944 (CVE-2021-44228, 100th pct); gate-eligible (>= 0.500 exploit-probability threshold)",
		EPSS:       &finding.ExploitScore{Peak: 0.944, Percentile: 1.0, CVE: "CVE-2021-44228"},
	}}, verdict.Policy{FailOnEligible: true})

	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// Parens are escaped in the PDF content stream (escapePDF), so match the
	// unparenthesized fragments the stream actually contains.
	if !strings.Contains(out, "Exploit prediction") || !strings.Contains(out, "0.944") {
		t.Error("EPSS score must render on its own line")
	}
	if !strings.Contains(out, "100.0th percentile") || !strings.Contains(out, "CVE-2021-44228") {
		t.Error("EPSS line must carry the percentile and peak CVE")
	}
	if !strings.Contains(out, "escalated to gate-eligible") {
		t.Error("a gate-eligible EPSS finding must state why it was escalated")
	}
	// De-duplication: the "peak EPSS …" note VC-008 embeds in the evidence must be
	// stripped from the displayed evidence so the score is not shown twice.
	if strings.Contains(out, "peak EPSS 0.944") {
		t.Error("the inline evidence EPSS note must be stripped in the PDF (shown once, on its own line)")
	}
	// The base evidence (the affected-by list) must survive the strip.
	if !strings.Contains(out, "is affected by CVE-2021-44228") {
		t.Error("stripping the EPSS note must not drop the rest of the evidence")
	}
}

// Without an EPSS score the report is unchanged: no EPSS line at all.
func TestPDFOmitsEPSSLineWhenAbsent(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/x@1.0.0", Kind: graph.KindPackage, Name: "x", Version: "1.0.0"})
	g.MarkRoot("pkg:npm/x@1.0.0")
	res := verdict.Evaluate(g, []finding.Finding{{
		CheckID: "VC-008", Axis: finding.AxisVuln, Severity: finding.SevMedium,
		GateClass: finding.GateAdvisory, Confidence: 1, NodeID: "pkg:npm/x@1.0.0",
		Title: "1 known vulnerability", Evidence: "x@1.0.0 is affected by CVE-2020-1111",
	}}, verdict.Policy{})
	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Exploit prediction") {
		t.Error("no-EPSS finding must not render an EPSS line")
	}
}

// datasourceStatsWithGaps builds a Stats value carrying n gaps.
func datasourceStatsWithGaps(n int) datasource.Stats {
	return datasource.Stats{Queried: 10, FromNet: 10 - n, Gaps: n}
}

// A real workspace produced 1,284 advisory findings and a 224-page report.
// Advisory findings are capped, but the cap must be DISCLOSED — a silent
// truncation is the exact failure this tool exists to avoid.
func TestPDFCapsAdvisoryFindingsWithDisclosure(t *testing.T) {
	g := graph.New()
	var fs []finding.Finding
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("pkg:npm/p%03d@1.0.0", i)
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Name: fmt.Sprintf("p%03d", i), Version: "1.0.0"})
		fs = append(fs, finding.Finding{
			CheckID: "VC-008", NodeID: id, GateClass: finding.GateAdvisory,
			Severity: finding.SevMedium, Confidence: 1, Title: fmt.Sprintf("advisory %d", i),
		})
	}
	res := verdict.Evaluate(g, fs, verdict.Policy{})
	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "further advisory finding") {
		t.Error("advisory cap was applied without disclosing the omission")
	}
	if !strings.Contains(out, "VC-008 x200") {
		t.Error("the by-check summary must state the true total")
	}
	shown := strings.Count(out, "advisory ")
	if shown > 60 {
		t.Errorf("cap not applied: roughly %d advisory entries rendered", shown)
	}
}

// Block and gate-eligible findings are the actionable ones and must never be
// capped, however many there are.
func TestPDFNeverCapsActionableFindings(t *testing.T) {
	g := graph.New()
	var fs []finding.Finding
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("pkg:npm/b%03d@1.0.0", i)
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Name: fmt.Sprintf("b%03d", i), Version: "1.0.0"})
		fs = append(fs, finding.Finding{
			CheckID: "VC-001", NodeID: id, GateClass: finding.GateBlock,
			Severity: finding.SevCritical, Confidence: 1, Title: fmt.Sprintf("blocked %d", i),
		})
	}
	res := verdict.Evaluate(g, fs, verdict.Policy{})
	var b bytes.Buffer
	if err := (PDF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for i := 0; i < 60; i++ {
		if !strings.Contains(out, fmt.Sprintf("blocked %d", i)) {
			t.Fatalf("block finding %d was omitted — actionable findings must never be capped", i)
		}
	}
}
