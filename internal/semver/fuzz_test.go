package semver

import "testing"

// FuzzParse drives arbitrary strings at the version parser. Registries carry
// non-semver tags routinely, so Parse must degrade to Valid=false rather than
// panic on any input (D-33).
func FuzzParse(f *testing.F) {
	f.Add("1.2.3")
	f.Add("v1.2.3")
	f.Add("1.2.3-beta.1")
	f.Add("1.2.3+build.5")
	f.Add("1.2.3-beta+meta")
	f.Add("1.2")
	f.Add("")
	f.Add("-")
	f.Add("+")
	f.Add("...")
	f.Add("99999999999999999999.0.0")
	f.Add("1.2.3-")

	f.Fuzz(func(t *testing.T, s string) {
		v := Parse(s)
		if !v.Valid {
			return
		}
		// A version reported valid must have non-negative components; a negative
		// one would invert ordering comparisons downstream.
		if v.Major < 0 || v.Minor < 0 || v.Patch < 0 {
			t.Fatalf("Parse(%q) reported valid with negative component: %+v", s, v)
		}
	})
}
