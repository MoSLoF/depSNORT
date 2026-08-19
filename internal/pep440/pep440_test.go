package pep440_test

import (
	"sort"
	"testing"

	"ihbv.io/depsnort/internal/pep440"
)

func TestParseAndNormalize(t *testing.T) {
	for _, tc := range []struct {
		in    string
		valid bool
	}{
		{"1.0", true}, {"v1.0", true}, {"1!2.0", true}, {"1.0a1", true},
		{"1.0alpha1", true}, {"1.0.beta2", true}, {"1.0rc1", true}, {"1.0c1", true},
		{"1.0.post1", true}, {"1.0-post1", true}, {"1.0_rev2", true},
		{"1.0.dev3", true}, {"1.0+ubuntu.1", true}, {"1.0a", true},
		{"", false}, {"abc", false}, {"1.0.x", false}, {"1.-2", false}, {"1.0+", false},
	} {
		if got := pep440.Parse(tc.in).Valid; got != tc.valid {
			t.Errorf("Parse(%q).Valid = %v, want %v", tc.in, got, tc.valid)
		}
	}
}

// The ordering PEP 440 mandates and semver gets wrong.
func TestOrdering(t *testing.T) {
	ordered := []string{
		"1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0",
		"1.0+local", "1.0.post1", "1.1", "2.0", "1!0.1",
	}

	for i := 0; i+1 < len(ordered); i++ {
		a, b := pep440.Parse(ordered[i]), pep440.Parse(ordered[i+1])
		if !a.Valid || !b.Valid {
			t.Fatalf("fixture invalid: %q=%v %q=%v", ordered[i], a.Valid, ordered[i+1], b.Valid)
		}
		if got := pep440.Compare(a, b); got >= 0 {
			t.Errorf("Compare(%q, %q) = %d, want < 0", ordered[i], ordered[i+1], got)
		}
	}
	// An epoch outranks any release number.
	if pep440.Compare(pep440.Parse("1!0.1"), pep440.Parse("99.0")) <= 0 {
		t.Error("epoch must outrank release")
	}
	// Trailing zeros are insignificant.
	if pep440.Compare(pep440.Parse("1.0"), pep440.Parse("1.0.0")) != 0 {
		t.Error("1.0 must equal 1.0.0")
	}
}

func TestSatisfies(t *testing.T) {
	for _, tc := range []struct {
		spec, ver       string
		want, evaluable bool
	}{
		{">=2.0", "2.31.0", true, true},
		{">=2.0", "1.9", false, true},
		{">=1.21,<2.0", "1.26.18", true, true},
		{">=1.21,<2.0", "2.0.7", false, true},
		{"==1.4.*", "1.4.7", true, true},
		{"==1.4.*", "1.5.0", false, true},
		{"!=1.4.*", "1.4.7", false, true},
		{"~=1.4.2", "1.4.9", true, true},
		{"~=1.4.2", "1.5.0", false, true},
		{"~=1.4.2", "1.4.1", false, true},
		{"===1.0+weird", "1.0+weird", true, true},
		{"", "1.0", true, true},

		// Pre-releases are excluded unless the specifier asks for one.
		{">=1.0", "2.0b1", false, true},
		{">=1.0b1", "2.0b1", true, true},
		{">=1.0", "1.5.dev1", false, true},

		// Exclusive bounds do not admit the excluded version's own pre/post.
		{"<1.7", "1.7rc1", false, true},
		{">1.7", "1.7.post1", false, true},
		{">1.7", "1.8", true, true},

		// Unreadable input declines rather than excluding.
		{">=notaversion", "1.0", false, false},
		{"^1.0", "1.0", false, false},
		{"1.0", "1.0", false, false},
		{"~=1", "1.5", false, false},
		{">=1.0", "notaversion", false, false},
	} {
		got, ev := pep440.Satisfies(tc.spec, tc.ver)
		if got != tc.want || ev != tc.evaluable {
			t.Errorf("Satisfies(%q, %q) = (%v, %v), want (%v, %v)",
				tc.spec, tc.ver, got, ev, tc.want, tc.evaluable)
		}
	}
}

// The property the walk depends on: picking the highest satisfying version.
func TestHighestSatisfyingIsStable(t *testing.T) {
	pub := []string{"2.0.0", "2.28.1", "2.31.0", "3.0.0b1", "3.0.0"}
	var ok []string
	for _, v := range pub {
		if sat, ev := pep440.Satisfies(">=2.0,<3", v); ev && sat {
			ok = append(ok, v)
		}
	}
	sort.Slice(ok, func(i, j int) bool {
		return pep440.Compare(pep440.Parse(ok[i]), pep440.Parse(ok[j])) > 0
	})
	if len(ok) == 0 || ok[0] != "2.31.0" {
		t.Errorf("highest satisfying = %v, want 2.31.0 first", ok)
	}
}

func FuzzParseNeverPanics(f *testing.F) {
	for _, s := range []string{"1.0", "1!2.0.post1.dev2+local", "v1.0a1", "", "..", "1.0.*"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v := pep440.Parse(s)
		if v.Valid {
			// A version that parses must compare with itself as equal.
			if pep440.Compare(v, v) != 0 {
				t.Fatalf("Compare(v, v) != 0 for %q", s)
			}
		}
		_, _ = pep440.Satisfies(">=1.0", s)
		_, _ = pep440.Satisfies(s, "1.0")
	})
}
