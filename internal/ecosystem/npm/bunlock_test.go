package npm

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// A minimal bun.lock exercising the shapes the reader must handle: JSONC
// (a comment + trailing commas), a scoped name, a devDependency (installed at
// root, so direct), a git descriptor, and a transitive chain
// (react -> loose-envify -> js-tokens) so real depths can be asserted.
const sampleBunLock = `{
  // bun text lockfile
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "my-app",
      "dependencies": {
        "react": "^18.2.0",
        "@scope/util": "^1.0.0",
        "leftpad-git": "github:someone/leftpad#abc123",
      },
      "devDependencies": {
        "typescript": "^5.0.0",
      },
    },
  },
  "packages": {
    "react": ["react@18.2.0", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-aaa"],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^4.0.0" }, "bin": { "loose-envify": "cli.js" } }, "sha512-bbb"],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-ccc"],
    "@scope/util": ["@scope/util@1.2.0", "", {}, "sha512-ddd"],
    "typescript": ["typescript@5.4.0", "", {}, "sha512-eee"],
    "leftpad-git": ["leftpad-git@github:someone/leftpad#abc123", {}, "someone-leftpad-abc123"],
  },
}`

func TestParseBunLock(t *testing.T) {
	g, err := parseBunLock([]byte(sampleBunLock))
	if err != nil {
		t.Fatalf("parseBunLock: %v", err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want one", g.Roots)
	}
	rootID := purl.NewNpm("my-app", "0.0.0").String()
	if g.Get(rootID) == nil {
		t.Fatalf("root %s missing", rootID)
	}

	react := purl.NewNpm("react", "18.2.0").String()
	loose := purl.NewNpm("loose-envify", "1.4.0").String()
	jstok := purl.NewNpm("js-tokens", "4.0.0").String()
	scoped := purl.NewNpm("@scope/util", "1.2.0").String()
	ts := purl.NewNpm("typescript", "5.4.0").String()

	for _, id := range []string{react, loose, jstok, scoped, ts} {
		if g.Get(id) == nil {
			t.Errorf("missing node %s", id)
		}
	}

	// Root direct edges (devDependencies are installed at root -> direct).
	for _, id := range []string{react, scoped, ts} {
		if !edgeExists(g, rootID, id) {
			t.Errorf("missing root edge -> %s", id)
		}
		if !g.Get(id).Direct {
			t.Errorf("%s should be Direct", id)
		}
	}

	// Transitive chain with real depths.
	if !edgeExists(g, react, loose) || !edgeExists(g, loose, jstok) {
		t.Error("missing react -> loose-envify -> js-tokens chain")
	}
	if edgeExists(g, rootID, jstok) {
		t.Error("js-tokens is transitive; it must not be a direct root edge")
	}
	if d := g.Get(jstok).Depth; d < 3 {
		t.Errorf("js-tokens depth = %d, want >= 3", d)
	}

	// Source classification: semver -> registry, github: -> git.
	if c := g.Get(react).Attr[graph.AttrSourceClass]; c != graph.SourceRegistry {
		t.Errorf("react source = %q, want registry", c)
	}
	gitID := purl.NewNpm("leftpad-git", "github:someone/leftpad#abc123").String()
	if n := g.Get(gitID); n == nil {
		t.Errorf("git dep node missing (id=%s)", gitID)
	} else if c := n.Attr[graph.AttrSourceClass]; c != graph.SourceGit {
		t.Errorf("leftpad-git source = %q, want git", c)
	}
}

func TestStripJSONC(t *testing.T) {
	in := `{
  // a line comment, with a comma
  "a": "keep // this and , this", /* block */
  "b": [1, 2, 3,],
  "c": {"x": 1,},
}`
	got := string(stripJSONC([]byte(in)))
	// The in-string "//" and "," must survive.
	if !contains(got, "keep // this and , this") {
		t.Errorf("in-string content was corrupted: %q", got)
	}
	// Comments must be gone.
	if contains(got, "line comment") || contains(got, "block") {
		t.Errorf("comment survived: %q", got)
	}
	// Trailing commas must be gone (before ] and }).
	if contains(got, "3,]") || contains(got, "1,}") {
		t.Errorf("trailing comma survived: %q", got)
	}
}

func TestSplitBunDescriptor(t *testing.T) {
	cases := []struct{ in, name, ver string }{
		{"react@18.2.0", "react", "18.2.0"},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3"},
		{"react@npm:preact@10.0.0", "react", "npm:preact@10.0.0"},
		{"pkg@github:o/r#sha", "pkg", "github:o/r#sha"},
		{"noversion", "noversion", ""},
	}
	for _, c := range cases {
		n, v := splitBunDescriptor(c.in)
		if n != c.name || v != c.ver {
			t.Errorf("splitBunDescriptor(%q) = (%q,%q), want (%q,%q)", c.in, n, v, c.name, c.ver)
		}
	}
}

func TestBunSource(t *testing.T) {
	cases := []struct {
		ver, class string
	}{
		{"18.2.0", graph.SourceRegistry},
		{"npm:preact@10", graph.SourceRegistry},
		{"github:o/r#sha", graph.SourceGit},
		{"git+https://x/y.git", graph.SourceGit},
		{"workspace:packages/foo", graph.SourcePath},
		{"file:../local", graph.SourcePath},
		{"https://example.com/x.tgz", graph.SourceURL},
	}
	for _, c := range cases {
		got, _ := bunSource(c.ver)
		if got != c.class {
			t.Errorf("bunSource(%q) class = %q, want %q", c.ver, got, c.class)
		}
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
