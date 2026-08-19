package builtin

import (
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/graph"
)

// realWorldFalsePositives is the complete VC-006 output from a scan of a real
// 58-repo workspace. Every single one is a legitimate, widely-used package —
// a 100% false-positive rate, which is what a warning tax looks like.
//
// They fall into three failure modes, and the fix must close all three:
//
//  1. SCOPED PACKAGES. `@vitest/utils` was compared on its bare name `utils`
//     against `util`. A scoped package is not impersonating an unscoped one —
//     the scope is explicit provenance. (Scope-squatting is a real but separate
//     attack, and needs its own check comparing scope to scope.)
//  2. LEGITIMATE NEAR-NEIGHBOURS. `preact` really is one edit from `react`;
//     `color` from `colors`; `scapy` from `scipy`. All are real packages that
//     predate any squat.
//  3. DISTANCE-2 ON SHORT-ISH NAMES. `commands`/`commander`,
//     `password`/`passport` are unrelated words that happen to sit two edits
//     apart.
var realWorldFalsePositives = []struct{ name, ecosystem string }{
	{"@astrojs/prism", "npm"}, {"@chevrotain/utils", "npm"}, {"@eslint/eslintrc", "npm"},
	{"@floating-ui/utils", "npm"}, {"@iconify/utils", "npm"}, {"@inquirer/password", "npm"},
	{"@ioredis/commands", "npm"}, {"@iovalkey/commands", "npm"}, {"@jest/console", "npm"},
	{"@jsonjoy.com/fs-node", "npm"}, {"@npmcli/redact", "npm"}, {"@pinojs/redact", "npm"},
	{"@protobufjs/inquire", "npm"}, {"@tanstack/table-core", "npm"}, {"@trpc/server", "npm"},
	{"@types/babel__core", "npm"}, {"@typescript-eslint/utils", "npm"}, {"@vitest/utils", "npm"},
	{"color", "npm"}, {"colord", "npm"}, {"commondir", "npm"}, {"crypt", "npm"},
	{"motion", "npm"}, {"preact", "npm"}, {"react-zdog", "npm"}, {"through", "npm"},
	{"tslint", "npm"},
	{"mkdoc", "pypi"}, {"scapy", "pypi"}, {"unicorn", "pypi"},
}

func TestVC006NoFalsePositivesOnRealWorkspace(t *testing.T) {
	g := graph.New()
	for i, fp := range realWorldFalsePositives {
		id := "pkg:" + fp.ecosystem + "/" + fp.name + "@1.0." + string(rune('0'+i%10))
		g.AddNode(&graph.Node{
			ID: id, Kind: graph.KindPackage, Ecosystem: fp.ecosystem,
			Name: fp.name, Version: "1.0.0",
		})
	}
	findings := (Typosquat{}).Run(&check.Context{Graph: g})
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("false positive: %s — %s", f.NodeID, f.Evidence)
		}
		t.Fatalf("VC-006 produced %d false positives on known-good packages", len(findings))
	}
}

// The fix must not blind the check. These are genuine squat shapes and must
// still fire.
func TestVC006StillCatchesRealSquats(t *testing.T) {
	cases := []struct{ name, ecosystem, imitates string }{
		{"expresss", "npm", "express"},   // doubled letter
		{"lodahs", "npm", "lodash"},      // transposition
		{"chalkk", "npm", "chalk"},       // doubled letter
		{"reqeusts", "pypi", "requests"}, // transposition
		{"nuxmpy", "pypi", "numpy"},      // scrambled
	}
	for _, c := range cases {
		g := graph.New()
		id := "pkg:" + c.ecosystem + "/" + c.name + "@1.0.0"
		g.AddNode(&graph.Node{
			ID: id, Kind: graph.KindPackage, Ecosystem: c.ecosystem,
			Name: c.name, Version: "1.0.0",
		})
		findings := (Typosquat{}).Run(&check.Context{Graph: g})
		if len(findings) == 0 {
			t.Errorf("missed a real squat: %s (imitating %s)", c.name, c.imitates)
		}
	}
}

// OPU-05: a versioned successor package (`cli-table3`, the maintained heir of
// the abandoned `cli-table`) differs from its corpus predecessor only by an
// appended version token, so pure edit distance reads it as a distance-1 squat.
// It must stay silent — while a genuine transposition squat of the same
// predecessor (`cli-tabel`) must still fire. This pins the boundary in both
// directions, the way the vouched-parent and real-squat tests pin theirs.
func TestVC006SuppressesVersionedSuccessorsButNotSquats(t *testing.T) {
	// Each is the corpus package `cli-table` plus only a numeric version token,
	// so each lands within the distance-2 ceiling with `cli-table` as its nearest
	// match — the exact shape that fired on the real npm/cli scan.
	silent := []string{
		"cli-table3",  // +1 digit, distance 1 — the real observed case
		"cli-table2",  // +1 digit, distance 1
		"cli-table-9", // separator + digit, distance 2
	}
	for _, name := range silent {
		g := graph.New()
		id := "pkg:npm/" + name + "@1.0.0"
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: name, Version: "1.0.0"})
		for _, f := range (Typosquat{}).Run(&check.Context{Graph: g}) {
			if f.NodeID == id {
				t.Errorf("versioned successor %q was flagged as a typosquat: %s", name, f.Evidence)
			}
		}
	}

	// The suppression must not blind the check to an actual squat of the same
	// predecessor: `cli-tabel` transposes two letters of `cli-table` and is not a
	// prefix-plus-version-token, so it still fires.
	fires := "cli-tabel"
	g := graph.New()
	id := "pkg:npm/" + fires + "@1.0.0"
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "npm", Name: fires, Version: "1.0.0"})
	var hit bool
	for _, f := range (Typosquat{}).Run(&check.Context{Graph: g}) {
		if f.NodeID == id {
			hit = true
		}
	}
	if !hit {
		t.Errorf("transposition squat %q should still fire", fires)
	}
}

// Provenance by association: a package pulled in BY a well-known package is not
// a squat — nobody typos their way into a transitive dependency.
func TestVC006SkipsPackagesVouchedForByPopularParents(t *testing.T) {
	g := graph.New()
	parent := "pkg:npm/express@4.19.2" // in the popular corpus
	child := "pkg:npm/expresss@1.0.0"  // would otherwise flag
	g.AddNode(&graph.Node{ID: parent, Kind: graph.KindPackage, Ecosystem: "npm", Name: "express", Version: "4.19.2"})
	g.AddNode(&graph.Node{ID: child, Kind: graph.KindPackage, Ecosystem: "npm", Name: "expresss", Version: "1.0.0"})
	g.AddEdge(parent, child, graph.EdgeDependsOn)

	for _, f := range (Typosquat{}).Run(&check.Context{Graph: g}) {
		if f.NodeID == child {
			t.Error("a package vouched for by a popular parent should not be flagged")
		}
	}
}
