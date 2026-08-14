package emit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/verdict"
)

// sarifInvocation0 pulls the single invocation Emit always constructs, so
// each test below doesn't repeat the same three type assertions.
func sarifInvocation0(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %#v, want exactly one run", parsed["runs"])
	}
	run := runs[0].(map[string]any)
	invocations, ok := run["invocations"].([]any)
	if !ok || len(invocations) != 1 {
		t.Fatalf("invocations = %#v, want exactly one invocation", run["invocations"])
	}
	return invocations[0].(map[string]any)
}

func TestSARIFEmptyFindingsIsEmptyArrayNotNull(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/x@1", Kind: graph.KindPackage, Name: "x"})
	g.MarkRoot("pkg:npm/x@1")
	res := verdict.Evaluate(g, nil, verdict.Policy{})

	var b bytes.Buffer
	if err := (SARIF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `"results": null`) {
		t.Fatalf("results serialized as null, not an empty array:\n%s", b.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(b.Bytes(), &parsed); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	run := parsed["runs"].([]any)[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("results = %#v, want an array", run["results"])
	}
	if len(results) != 0 {
		t.Errorf("results = %v, want empty", results)
	}
}

// FN-01: a SARIF-only consumer must be able to tell "nothing found" from
// "the scan could not look" without ever touching the JSON report.
func TestSARIFDegradedCoverageProducesNotification(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/x@1", Kind: graph.KindPackage, Name: "x"})
	g.MarkRoot("pkg:npm/x@1")
	res := verdict.Result{
		Coverage: graph.Coverage{Complete: false, Degraded: true, DataSourceGaps: []string{"osv"}},
	}

	var b bytes.Buffer
	if err := (SARIF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	inv := sarifInvocation0(t, b.Bytes())
	notes, _ := inv["toolExecutionNotifications"].([]any)
	if len(notes) == 0 {
		t.Fatal("degraded coverage produced no notifications")
	}
	found := false
	for _, raw := range notes {
		n := raw.(map[string]any)
		text := n["message"].(map[string]any)["text"].(string)
		if n["level"] == "warning" && strings.Contains(text, "osv") && strings.Contains(strings.ToLower(text), "incomplete") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning notification mentions osv/incomplete: %v", notes)
	}
}

// Flat resolution is a lockfile-format limitation, not a scan degradation
// (coverage.go's own Degraded doc comment) — stderr never warns on this
// alone today, and SARIF must not either.
func TestSARIFFlatResolutionProducesNoteNotWarning(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:pypi/x@1", Kind: graph.KindPackage, Name: "x"})
	g.MarkRoot("pkg:pypi/x@1")
	cov := graph.Coverage{Complete: true, FlatEcosystems: []string{"pypi"}}
	if cov.Incomplete() {
		t.Fatal("test setup invalid: flat-only coverage must not be Incomplete()")
	}
	res := verdict.Result{Coverage: cov}

	var b bytes.Buffer
	if err := (SARIF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	inv := sarifInvocation0(t, b.Bytes())
	notes, _ := inv["toolExecutionNotifications"].([]any)
	if len(notes) != 1 {
		t.Fatalf("notifications = %d, want exactly 1: %v", len(notes), notes)
	}
	n := notes[0].(map[string]any)
	if n["level"] != "note" {
		t.Errorf("level = %v, want %q", n["level"], "note")
	}
	text := n["message"].(map[string]any)["text"].(string)
	if !strings.Contains(text, "pypi") {
		t.Errorf("note does not name the flat ecosystem: %q", text)
	}
}

func TestSARIFCleanRunHasNoNotifications(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:npm/x@1", Kind: graph.KindPackage, Name: "x"})
	g.MarkRoot("pkg:npm/x@1")
	res := verdict.Evaluate(g, nil, verdict.Policy{})
	if res.Coverage.Incomplete() || len(res.Coverage.FlatEcosystems) != 0 {
		t.Fatalf("test setup invalid: expected fully clean coverage, got %+v", res.Coverage)
	}

	var b bytes.Buffer
	if err := (SARIF{}).Emit(&b, g, res, RunInfo{}); err != nil {
		t.Fatal(err)
	}
	inv := sarifInvocation0(t, b.Bytes())
	if es, _ := inv["executionSuccessful"].(bool); !es {
		t.Error("executionSuccessful = false, want true")
	}
	if notes, ok := inv["toolExecutionNotifications"]; ok {
		t.Errorf("clean run should omit toolExecutionNotifications, got %v", notes)
	}
}
