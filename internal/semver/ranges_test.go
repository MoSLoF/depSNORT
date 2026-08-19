package semver

import (
	"sort"
	"testing"
)

func TestSatisfies(t *testing.T) {
	for _, tc := range []struct {
		rng, ver        string
		want, evaluable bool
	}{
		// caret
		{"^1.2.3", "1.2.3", true, true},
		{"^1.2.3", "1.9.0", true, true},
		{"^1.2.3", "2.0.0", false, true},
		{"^1.2.3", "1.2.2", false, true},
		{"^0.2.3", "0.2.9", true, true},
		{"^0.2.3", "0.3.0", false, true},
		{"^0.0.3", "0.0.3", true, true},
		{"^0.0.3", "0.0.4", false, true},
		// tilde
		{"~1.2.3", "1.2.9", true, true},
		{"~1.2.3", "1.3.0", false, true},
		{"~1", "1.9.9", true, true},
		{"~1", "2.0.0", false, true},
		// comparators, partial completion
		{">=2.0", "2.0.0", true, true},
		{">=2.0", "1.9.9", false, true},
		{">1.2.3 <2.0.0", "1.5.0", true, true},
		{">1.2.3 <2.0.0", "2.0.0", false, true},
		// x-ranges
		{"1.2.x", "1.2.7", true, true},
		{"1.2.x", "1.3.0", false, true},
		{"1.x", "1.9.9", true, true},
		{"1.x", "2.0.0", false, true},
		{"*", "5.4.3", true, true},
		{"", "5.4.3", true, true},
		// hyphen ranges
		{"1.2.3 - 2.3.4", "2.3.4", true, true},
		{"1.2.3 - 2.3.4", "2.3.5", false, true},
		{"1.2.3 - 2.3", "2.3.9", true, true},
		{"1.2.3 - 2.3", "2.4.0", false, true},
		// OR
		{"^1.0.0 || ^2.0.0", "2.5.0", true, true},
		{"^1.0.0 || ^2.0.0", "3.0.0", false, true},
		// exact
		{"1.2.3", "1.2.3", true, true},
		{"1.2.3", "1.2.4", false, true},
		// prerelease: excluded unless a comparator names one at the same tuple
		{"^1.0.0", "2.0.0-beta.1", false, true},
		{">=1.0.0", "1.5.0-alpha", false, true},
		{">=1.5.0-alpha", "1.5.0-alpha.1", true, true},
		// unreadable -> declines
		{"not-a-range", "1.0.0", false, false},
		{"^1.x.3", "1.4.3", false, false},
		{">=1.0.0", "not-a-version", false, false},
		{"1.2.3.4", "1.2.3", false, false},
	} {
		got, ev := Satisfies(tc.rng, tc.ver)
		if got != tc.want || ev != tc.evaluable {
			t.Errorf("Satisfies(%q, %q) = (%v, %v), want (%v, %v)",
				tc.rng, tc.ver, got, ev, tc.want, tc.evaluable)
		}
	}
}

// The property the walk relies on: pick the highest published version a range
// admits, and never a pre-release unless asked.
func TestHighestSatisfying(t *testing.T) {
	pub := []string{"1.0.0", "1.4.2", "1.9.0", "2.0.0-rc.1", "2.0.0"}
	var ok []string
	for _, v := range pub {
		if sat, ev := Satisfies("^1.0.0", v); ev && sat {
			ok = append(ok, v)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return Parse(ok[i]).Compare(Parse(ok[j])) > 0 })
	if len(ok) == 0 || ok[0] != "1.9.0" {
		t.Errorf("highest satisfying ^1.0.0 = %v, want 1.9.0 first", ok)
	}
}

func FuzzSatisfiesNeverPanics(f *testing.F) {
	for _, s := range []string{"^1.2.3", "~1.0", "1.x", "1.2.3 - 2.0.0", ">=1 <2 || ^3", "*"} {
		f.Add(s, "1.5.0")
	}
	f.Fuzz(func(t *testing.T, rng, ver string) {
		_, _ = Satisfies(rng, ver)
	})
}

func TestSatisfiesCargo(t *testing.T) {
	for _, tc := range []struct {
		req, ver        string
		want, evaluable bool
	}{
		// bare version is caret, NOT exact — the key Cargo difference
		{"1.2.3", "1.2.3", true, true},
		{"1.2.3", "1.9.0", true, true},
		{"1.2.3", "2.0.0", false, true},
		{"1.2.3", "1.2.2", false, true},
		// caret 0.x rules
		{"0.2.3", "0.2.9", true, true},
		{"0.2.3", "0.3.0", false, true},
		{"^0.0.3", "0.0.3", true, true},
		{"^0.0.3", "0.0.4", false, true},
		{"^0", "0.9.9", true, true},
		{"^0", "1.0.0", false, true},
		// tilde
		{"~1.2", "1.2.9", true, true},
		{"~1.2", "1.3.0", false, true},
		// comma is AND
		{">=1.2, <1.5", "1.4.0", true, true},
		{">=1.2, <1.5", "1.5.0", false, true},
		// explicit exact and wildcard
		{"=1.2.3", "1.2.3", true, true},
		{"=1.2.3", "1.2.4", false, true},
		{"1.*", "1.9.0", true, true},
		{"1.*", "2.0.0", false, true},
		{"*", "9.9.9", true, true},
		// declines
		{">=1.x.0", "1.0.0", false, false},
		{"~1.2.3.4", "1.2.3", false, false},
	} {
		got, ev := SatisfiesCargo(tc.req, tc.ver)
		if got != tc.want || ev != tc.evaluable {
			t.Errorf("SatisfiesCargo(%q, %q) = (%v, %v), want (%v, %v)",
				tc.req, tc.ver, got, ev, tc.want, tc.evaluable)
		}
	}
}

func TestSatisfiesRuby(t *testing.T) {
	for _, tc := range []struct {
		req, ver        string
		want, evaluable bool
	}{
		// pessimistic ~>
		{"~> 1.2", "1.9.0", true, true},
		{"~> 1.2", "2.0.0", false, true},
		{"~> 1.2.3", "1.2.9", true, true},
		{"~> 1.2.3", "1.3.0", false, true},
		{"~> 1", "1.9.9", true, true},
		{"~> 1", "2.0.0", false, true},
		// bare is exact
		{"1.2.3", "1.2.3", true, true},
		{"1.2.3", "1.2.4", false, true},
		// comparators, comma AND, !=
		{">= 1.2, < 2.0", "1.5.0", true, true},
		{">= 1.2, < 2.0", "2.0.0", false, true},
		{"!= 1.2.3", "1.2.3", false, true},
		{"!= 1.2.3", "1.2.4", true, true},
		// declines
		{"~> 1.x", "1.2.0", false, false},
		{">= notaver", "1.0.0", false, false},
	} {
		got, ev := SatisfiesRuby(tc.req, tc.ver)
		if got != tc.want || ev != tc.evaluable {
			t.Errorf("SatisfiesRuby(%q,%q) = (%v,%v), want (%v,%v)", tc.req, tc.ver, got, ev, tc.want, tc.evaluable)
		}
	}
}

func TestSatisfiesComposer(t *testing.T) {
	for _, tc := range []struct {
		req, ver        string
		want, evaluable bool
	}{
		// caret (npm-like)
		{"^1.2.3", "1.9.0", true, true},
		{"^1.2.3", "2.0.0", false, true},
		// tilde is PESSIMISTIC, differs from npm: ~1.2 -> <2.0
		{"~1.2", "1.9.0", true, true},
		{"~1.2", "2.0.0", false, true},
		{"~1.2.3", "1.2.9", true, true},
		{"~1.2.3", "1.3.0", false, true},
		// space and comma AND, || OR
		{">=1.0 <2.0", "1.5.0", true, true},
		{">=1.0,<2.0", "1.5.0", true, true},
		{"^1.0 || ^2.0", "2.5.0", true, true},
		{"^1.0 || ^2.0", "3.0.0", false, true},
		// wildcard and exact
		{"1.2.*", "1.2.7", true, true},
		{"1.2.*", "1.3.0", false, true},
		{"1.2.3", "1.2.3", true, true},
		{"*", "9.9.9", true, true},
		// declines
		{"dev-main", "1.0.0", false, false},
		{"^1.0@dev", "1.0.0", false, false},
	} {
		got, ev := SatisfiesComposer(tc.req, tc.ver)
		if got != tc.want || ev != tc.evaluable {
			t.Errorf("SatisfiesComposer(%q,%q) = (%v,%v), want (%v,%v)", tc.req, tc.ver, got, ev, tc.want, tc.evaluable)
		}
	}
}
