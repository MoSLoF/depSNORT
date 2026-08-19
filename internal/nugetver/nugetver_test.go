package nugetver

import (
	"sort"
	"testing"
)

func TestParseFourPart(t *testing.T) {
	for _, tc := range []struct {
		in    string
		valid bool
	}{
		{"1.0", true}, {"1.2.3", true}, {"1.2.3.4", true}, {"1.0.0-beta", true},
		{"1.0.0-rc.2", true}, {"1.2.3.4-pre+meta", true},
		{"1", false}, {"", false}, {"1.2.3.4.5", false}, {"1.x", false}, {"abc", false},
	} {
		if got := Parse(tc.in).Valid; got != tc.valid {
			t.Errorf("Parse(%q).Valid = %v, want %v", tc.in, got, tc.valid)
		}
	}
}

func TestOrdering(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0", "1.0.0.1", "1.0.1", "1.1.0", "2.0.0"}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := Parse(ordered[i]), Parse(ordered[i+1])
		if !a.Valid || !b.Valid {
			t.Fatalf("fixture invalid: %q %q", ordered[i], ordered[i+1])
		}
		if Compare(a, b) >= 0 {
			t.Errorf("Compare(%q,%q) >= 0, want <", ordered[i], ordered[i+1])
		}
	}
	// The 4th component orders: 1.0.0.1 > 1.0.0.
	if Compare(Parse("1.0.0.1"), Parse("1.0.0")) <= 0 {
		t.Error("revision component must order above the 3-part release")
	}
}

func TestSatisfies(t *testing.T) {
	for _, tc := range []struct {
		rng, ver        string
		want, evaluable bool
	}{
		// bare = minimum (NOT exact)
		{"1.0", "1.0", true, true},
		{"1.0", "1.5", true, true},
		{"1.0", "0.9", false, true},
		// exact
		{"[1.0]", "1.0", true, true},
		{"[1.0]", "1.0.1", false, true},
		// half-open and closed intervals
		{"[1.0,2.0)", "1.0", true, true},
		{"[1.0,2.0)", "1.9.9", true, true},
		{"[1.0,2.0)", "2.0", false, true},
		{"(1.0,2.0)", "1.0", false, true},
		{"[1.0,2.0]", "2.0", true, true},
		{"(,2.0]", "1.5", true, true},
		{"(,2.0]", "2.1", false, true},
		{"[1.0,)", "5.0", true, true},
		{"(1.0,)", "1.0", false, true},
		// four-part versions inside a range
		{"[1.2.3.4,2.0)", "1.2.3.5", true, true},
		{"[1.2.3.4,2.0)", "1.2.3.3", false, true},
		// prerelease excluded unless a bound names one
		{"[1.0,2.0)", "1.5.0-beta", false, true},
		{"[1.0-alpha,2.0)", "1.5.0-beta", true, true},
		// declines
		{"[1.0", "1.0", false, false},
		{"(,)", "1.0", false, false},
		{"[bad,2.0)", "1.5", false, false},
		{"[1.0,2.0)", "not-a-version", false, false},
	} {
		got, ev := Satisfies(tc.rng, tc.ver)
		if got != tc.want || ev != tc.evaluable {
			t.Errorf("Satisfies(%q,%q) = (%v,%v), want (%v,%v)", tc.rng, tc.ver, got, ev, tc.want, tc.evaluable)
		}
	}
}

// NuGet resolves to the LOWEST satisfying version, the opposite of npm/Cargo.
// The walk relies on being able to pick that end deterministically.
func TestLowestSatisfying(t *testing.T) {
	pub := []string{"1.0.0", "1.2.0", "1.5.0", "2.0.0"}
	var ok []string
	for _, v := range pub {
		if s, ev := Satisfies("[1.0,2.0)", v); ev && s {
			ok = append(ok, v)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return Compare(Parse(ok[i]), Parse(ok[j])) < 0 })
	if len(ok) == 0 || ok[0] != "1.0.0" {
		t.Errorf("lowest satisfying [1.0,2.0) = %v, want 1.0.0 first", ok)
	}
}

func FuzzParseNeverPanics(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "1.0.0-rc.1+meta", "[1.0,2.0)", "(,1.0]", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v := Parse(s); v.Valid && Compare(v, v) != 0 {
			t.Fatalf("Compare(v,v) != 0 for %q", s)
		}
		_, _ = Satisfies(s, "1.0.0")
		_, _ = Satisfies("[1.0,2.0)", s)
	})
}
