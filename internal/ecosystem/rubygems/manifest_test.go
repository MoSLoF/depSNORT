package rubygems

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// OPU-16: a Gemfile with no Gemfile.lock is claimed and parsed manifest-only,
// its declared gems riding to the expansion tier — not disclosed as an
// unresolvable gap and left unscanned.
func TestGemfileManifestOnlyClaim(t *testing.T) {
	a := New()
	dir := "testdata/gemfile-only"
	if !a.Detect(dir) {
		t.Fatal("should Detect a directory with a lock-less Gemfile")
	}
	if !a.Detect(filepath.Join(dir, "Gemfile")) {
		t.Fatal("should Detect a Gemfile file directly")
	}

	g, err := a.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}
	root := g.Get(g.Roots[0])
	if root.Attr[graph.AttrFlatResolution] != "gem" {
		t.Errorf("AttrFlatResolution = %q, want gem (manifest-only degrades coverage)", root.Attr[graph.AttrFlatResolution])
	}

	// source / ruby / group / gemspec / comment lines are ignored; the six gem
	// declarations (including the one nested in a group block) are read.
	want := map[string]string{
		"rails":       "~> 7.0",
		"puma":        ">= 5.0, < 6.0",
		"pg":          "",
		"redis":       "", // require: false is an option, not a constraint
		"nokogiri":    "", // github: source is an option; still scanned by name
		"rspec-rails": "~> 6.0",
	}
	got := map[string]string{}
	for _, d := range root.DeclaredDepsOf() {
		got[d.Name] = d.Constraint
	}
	if len(got) != len(want) {
		t.Fatalf("declared deps = %v, want %d entries", got, len(want))
	}
	for name, c := range want {
		if got[name] != c {
			t.Errorf("gem %q constraint = %q, want %q", name, got[name], c)
		}
	}
	if root.Attr[graph.AttrUnresolvedCount] != "6" {
		t.Errorf("AttrUnresolvedCount = %q, want 6", root.Attr[graph.AttrUnresolvedCount])
	}
}

// OPU-16: a Gemfile.lock (a resolved tree) still wins when both files are
// present — observed versions beat presumed.
func TestGemfileLockPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte("gem 'only_in_gemfile'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n"
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := New().Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	root := g.Get(g.Roots[0])
	if root.Attr[graph.AttrFlatResolution] == "gem" {
		t.Error("lock present but resolved manifest-only — the lock should win")
	}
	if g.Get("pkg:gem/rake@13.0.6") == nil {
		t.Error("resolved gem from the lock missing — lock precedence broken")
	}
}

// A Gemfile that declares no gems (only source/ruby) resolves to an error the
// scan flow turns into incomplete coverage, never a silent clean pass.
func TestGemfileNoGemsIsError(t *testing.T) {
	if _, err := parseGemfile("proj", []byte("source 'https://rubygems.org'\nruby '3.2.0'\n")); err == nil {
		t.Error("a gem-less Gemfile must return an error")
	}
	// A directory with such a Gemfile must also not be claimed.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Gemfile"), []byte("source 'https://rubygems.org'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if New().Detect(dir) {
		t.Error("a Gemfile declaring no gems must not be Detected as a project")
	}
}

func TestParseGemLine(t *testing.T) {
	cases := []struct {
		line       string
		name       string
		constraint string
		ok         bool
	}{
		{`gem 'rails', '~> 7.0'`, "rails", "~> 7.0", true},
		{`  gem "puma", '>= 5.0', '< 6.0'`, "puma", ">= 5.0, < 6.0", true},
		{`gem 'pg'`, "pg", "", true},
		{`gem 'redis', require: false`, "redis", "", true},
		{`gem 'nokogiri', github: 'x/y' # comment`, "nokogiri", "", true},
		{`gem 'x', :require => false`, "x", "", true},
		{`gem('rack', '3.0')`, "rack", "3.0", true},
		{`# gem 'commented'`, "", "", false},
		{`gemspec`, "", "", false},
		{`source 'https://rubygems.org'`, "", "", false},
		{`ruby '3.2.0'`, "", "", false},
		{`group :test do`, "", "", false},
		{``, "", "", false},
	}
	for _, c := range cases {
		name, constraint, ok := parseGemLine(c.line)
		if ok != c.ok || name != c.name || constraint != c.constraint {
			t.Errorf("parseGemLine(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.line, name, constraint, ok, c.name, c.constraint, c.ok)
		}
	}
}
