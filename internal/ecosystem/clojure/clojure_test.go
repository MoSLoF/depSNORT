package clojure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// The jepsen shape that motivated D-162: literal pins must resolve as observed
// direct dependencies with Maven coordinates.
const jepsenProjectClj = `(defproject swytch.jepsen "0.1.0"
  :description "Jepsen harness" ; not a dependency
  :dependencies [[org.clojure/clojure "1.12.4"]
                 [org.postgresql/postgresql "42.7.4"]
                 [com.taoensso/carmine "3.5.0" :exclusions [org.clojure/clojure]]
                 [postgresql-bare "9.9.9"]])
`

func writeManifest(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func resolve(t *testing.T, dir string) *graph.Graph {
	t.Helper()
	a := New()
	if !a.Detect(dir) {
		t.Fatalf("Detect(%s) = false, want true", dir)
	}
	g, err := a.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return g
}

func nodeByID(g *graph.Graph, id string) *graph.Node { return g.Nodes[id] }

func TestProjectCljResolvesLiteralPins(t *testing.T) {
	g := resolve(t, writeManifest(t, "project.clj", jepsenProjectClj))

	want := map[string]string{
		"pkg:maven/org.postgresql/postgresql@42.7.4": "org.postgresql:postgresql",
		"pkg:maven/org.clojure/clojure@1.12.4":       "org.clojure:clojure",
		"pkg:maven/com.taoensso/carmine@3.5.0":       "com.taoensso:carmine",
		// Bare symbol: group == artifact, Leiningen's own convention.
		"pkg:maven/postgresql-bare/postgresql-bare@9.9.9": "postgresql-bare:postgresql-bare",
	}
	for id, name := range want {
		n := nodeByID(g, id)
		if n == nil {
			t.Errorf("missing node %s", id)
			continue
		}
		if n.Ecosystem != "maven" || n.Name != name || !n.Direct || n.Depth != 1 {
			t.Errorf("node %s = eco %q name %q direct %v depth %d", id, n.Ecosystem, n.Name, n.Direct, n.Depth)
		}
		if n.Attr[graph.AttrSourceClass] != graph.SourceRegistry {
			t.Errorf("node %s source class = %q, want registry", id, n.Attr[graph.AttrSourceClass])
		}
	}

	// Root identity comes from defproject; flat resolution is disclosed.
	root := nodeByID(g, "pkg:maven/swytch.jepsen@0.1.0")
	if root == nil {
		t.Fatalf("missing defproject-named root; nodes: %v", ids(g))
	}
	if root.Attr[graph.AttrFlatResolution] != "maven" {
		t.Error("flat resolution must be disclosed: the formats record no transitive structure")
	}
	if root.Attr[graph.AttrUnresolved] != "" {
		t.Errorf("fully-pinned manifest must have nothing unresolved, got %q", root.Attr[graph.AttrUnresolved])
	}
}

func TestProjectCljDisclosesWhatItCannotPin(t *testing.T) {
	src := `(defproject x "1"
  :dependencies [[good/dep "1.0.0"]
                 [ranged/dep "[1.0,2.0)"]      ; a range is not a pin
                 [meta/dep "RELEASE"]          ; meta-version
                 [symver/dep my-version]       ; build-time symbol
                 #_[discarded/dep "6.6.6"]     ; reader-discarded: not declared
                 [org.clojure/clojure "1.12.4"]])
`
	g := resolve(t, writeManifest(t, "project.clj", src))

	if n := nodeByID(g, "pkg:maven/good/dep@1.0.0"); n == nil {
		t.Error("literal pin beside unresolvable entries must still resolve")
	}
	if n := nodeByID(g, "pkg:maven/discarded/dep@6.6.6"); n != nil {
		t.Error("a #_ discarded entry is not a declaration and must not resolve")
	}
	var root *graph.Node
	for _, id := range g.Roots {
		root = g.Nodes[id]
	}
	unres := root.Attr[graph.AttrUnresolved]
	for _, want := range []string{"ranged:dep", "meta:dep", "symver:dep"} {
		if !strings.Contains(unres, want) {
			t.Errorf("unresolved %q must include %s", unres, want)
		}
	}
	if strings.Contains(unres, "discarded") {
		t.Errorf("discarded entry leaked into unresolved: %q", unres)
	}
}

func TestDepsEdnResolvesAndClassifiesSources(t *testing.T) {
	src := `{:paths ["src"]
 :deps {org.postgresql/postgresql {:mvn/version "42.7.4"}
        io.github.someone/gitlib   {:git/url "https://github.com/someone/gitlib" :git/sha "abc123"}
        local/thing                {:local/root "../thing"}}
 :aliases {:test {:extra-deps {org.clojure/test.check {:mvn/version "1.1.1"}}}}}
`
	g := resolve(t, writeManifest(t, "deps.edn", src))

	if n := nodeByID(g, "pkg:maven/org.postgresql/postgresql@42.7.4"); n == nil {
		t.Error(":mvn/version literal must resolve")
	}
	// Alias extra-deps are the same fetch surface.
	if n := nodeByID(g, "pkg:maven/org.clojure/test.check@1.1.1"); n == nil {
		t.Error(":aliases :extra-deps must be read")
	}
	// Git and local coordinates carry their source class — disclosed, not
	// laundered into registry coordinates.
	var git, local *graph.Node
	for _, n := range g.SortedNodes() {
		switch n.Attr[graph.AttrSourceClass] {
		case graph.SourceGit:
			git = n
		case graph.SourcePath:
			local = n
		}
	}
	if git == nil || git.Attr[graph.AttrSourceRef] != "https://github.com/someone/gitlib" {
		t.Errorf("git coordinate must carry SourceGit + ref, got %+v", git)
	}
	if local == nil || local.Attr[graph.AttrSourceRef] != "../thing" {
		t.Errorf(":local/root coordinate must carry SourcePath + ref, got %+v", local)
	}
}

func TestDetectRefusesWhatItShould(t *testing.T) {
	// A dependency-less project.clj does not claim the directory (the Gemfile
	// declares-something bar): legitimately nothing to scan, not an error.
	dir := writeManifest(t, "project.clj", `(defproject empty "1.0" :description "no deps")`)
	if New().Detect(dir) {
		t.Error("a dependency-less project.clj must not claim the directory")
	}
	// An unrelated directory is not claimed.
	if New().Detect(t.TempDir()) {
		t.Error("an empty directory must not be claimed")
	}
}

func TestCommentsAndStringsAreNotDependencies(t *testing.T) {
	src := `(defproject x "1"
  ;; :dependencies [[evil/from-comment "6.6.6"]]
  :description "docs say :dependencies [[evil/from-string \"6.6.6\"]] here"
  :dependencies [[real/dep "1.0.0"]])
`
	g := resolve(t, writeManifest(t, "project.clj", src))
	for _, n := range g.SortedNodes() {
		if strings.Contains(n.ID, "evil") {
			t.Errorf("dependency manufactured from comment or string: %s", n.ID)
		}
	}
	if n := nodeByID(g, "pkg:maven/real/dep@1.0.0"); n == nil {
		t.Error("the real dependency must still resolve")
	}
}

func ids(g *graph.Graph) []string {
	var out []string
	for _, n := range g.SortedNodes() {
		out = append(out, n.ID)
	}
	return out
}
