package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A single top-level pin in a real project drags in layers the manifest never
// names. This fixture puts a lifecycle-hook payload TWO layers below the root —
// root -> layer1 -> poisoned-core — and asserts the scan resolves down to it
// and blocks, through the real CLI end to end.
//
// It is the install-surface companion to the registry-walk test in
// internal/ecosystem/pypi: this one proves the tool reads a payload buried
// past the directly-declared layer when a lockfile pins the chain; that one
// proves the tool DISCOVERS the buried layer when no lockfile does.
func TestTransitivePostinstallIsBlockedAtDepthTwo(t *testing.T) {
	const dir = "../../testdata/adversarial/npm-transitive-postinstall"
	out := filepath.Join(t.TempDir(), "report.json")

	code := run([]string{"scan", "-no-osv", "-no-registry", "-o", out, dir})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (block) — a depth-2 hook must gate", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Nodes []struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			Depth int    `json:"depth"`
			Risk  string `json:"risk"`
		} `json:"nodes"`
		Verdict struct {
			Coverage struct {
				Complete bool `json:"complete"`
			} `json:"coverage"`
		} `json:"verdict"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	// The chain must have resolved all the way down: a scan that stopped at the
	// directly-declared layer would miss the payload and still say "complete",
	// which is the false all-clear D-24 exists to prevent.
	if !doc.Verdict.Coverage.Complete {
		t.Error("coverage not complete — the transitive chain did not fully resolve")
	}

	var poisonedDepth = -1
	var poisonedRisk, layer1Risk string
	for _, n := range doc.Nodes {
		switch {
		case n.Kind == "package" && contains(n.ID, "poisoned-core"):
			poisonedDepth, poisonedRisk = n.Depth, n.Risk
		case n.Kind == "package" && contains(n.ID, "layer1"):
			layer1Risk = n.Risk
		}
	}

	if poisonedDepth != 2 {
		t.Errorf("poisoned-core resolved at depth %d, want 2 (it is not a direct dependency)", poisonedDepth)
	}
	if poisonedRisk != "flagged" {
		t.Errorf("poisoned-core risk = %q, want flagged", poisonedRisk)
	}
	// The inert hop must NOT be flagged: the finding belongs to the package
	// that carries the hook, not to everything on the path to it.
	if layer1Risk != "clean" {
		t.Errorf("layer1 risk = %q, want clean — the hop carries no hook", layer1Risk)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
