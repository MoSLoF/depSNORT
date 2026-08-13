package purl

import "testing"

// FuzzParse drives arbitrary strings at the PURL parser. PURL is depsnort's
// canonical identity: every node, every IOC ledger match, and every cross-repo
// blast-radius merge keys off it, so a parser that panics or round-trips
// incorrectly corrupts identity itself (D-33).
func FuzzParse(f *testing.F) {
	f.Add("pkg:npm/lodash@4.17.21")
	f.Add("pkg:npm/%40scope%2Fname@1.0.0")
	f.Add("pkg:pypi/flask@2.0.1")
	f.Add("pkg:gem/rake@13.0.6")
	f.Add("pkg:cargo/serde@1.0.0")
	f.Add("pkg:composer/vendor/pkg@1.0")
	f.Add("pkg:nuget/Newtonsoft.Json@13.0.3")
	f.Add("pkg:npm/a@1?qualifier=x#subpath")
	f.Add("pkg:")
	f.Add("pkg:npm/")
	f.Add("not-a-purl")
	f.Add("")
	f.Add("pkg:npm/@@@@@@@")
	f.Add("pkg:npm/a@1@2@3")

	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err != nil {
			return
		}
		// A successfully parsed PURL must render to a non-empty string, and that
		// rendering must itself parse — identity has to be stable, or the same
		// package can appear as two nodes.
		out := p.String()
		if out == "" {
			t.Fatalf("Parse(%q) succeeded but String() is empty", s)
		}
		p2, err := Parse(out)
		if err != nil {
			t.Fatalf("Parse(%q) -> String() = %q, which fails to re-parse: %v", s, out, err)
		}
		if got := p2.String(); got != out {
			t.Fatalf("round-trip not stable: %q -> %q -> %q", s, out, got)
		}
	})
}
