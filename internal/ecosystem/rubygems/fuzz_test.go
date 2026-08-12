package rubygems

import "testing"

// FuzzParseGemfileLock drives arbitrary bytes at the Gemfile.lock reader — an
// indentation-sensitive, hand-rolled format parser, the classic home of
// off-by-one slicing bugs (D-33).
func FuzzParseGemfileLock(f *testing.F) {
	f.Add([]byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n"))
	f.Add([]byte("GEM\n  specs:\n    a (1.0)\n      b (>= 2.0)\n    b (2.0)\n\nDEPENDENCIES\n  a\n"))
	f.Add([]byte("PATH\n  remote: .\n  specs:\n    local (0.1.0)\n"))
	f.Add([]byte("GEM\n  specs:\n    weird (\n"))
	f.Add([]byte("    (1.0)\n"))
	f.Add([]byte("GEM\n  specs:\n" + "    deep (1.0)\n      x (~> 1)\n        y (2)\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		g, err := parseGemfileLock("Gemfile.lock", raw)
		if err != nil {
			return
		}
		if g == nil {
			t.Fatal("nil graph with nil error")
		}
		_ = g.Coverage()
		_ = g.Orphans()
	})
}

// FuzzParseGemSpec drives the spec-line splitter directly: it slices on
// parentheses and spaces, so a line with unbalanced or absent delimiters is the
// shape that breaks it.
func FuzzParseGemSpec(f *testing.F) {
	f.Add("rake (13.0.6)")
	f.Add("name (>= 1.0, < 2.0)")
	f.Add("unbalanced (1.0")
	f.Add("()")
	f.Add("")
	f.Add("   ")

	f.Fuzz(func(t *testing.T, s string) {
		name, ver := parseGemSpec(s)
		_, _ = name, ver
		n2, v2 := parseGemDep(s)
		_, _ = n2, v2
	})
}
