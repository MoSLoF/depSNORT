package builtin

import "testing"

// D-33. osaDistanceBounded is an optimization of osaDistance, so the only thing
// that matters is that it never changes an answer the caller can observe: for
// any pair whose true distance is within the ceiling, it must return that exact
// distance; otherwise it must report something above the ceiling.

func TestBoundedAgreesWithExact(t *testing.T) {
	pairs := [][2]string{
		{"lodash", "lodash"}, {"lodash", "lodahs"}, {"lodash", "l0dash"},
		{"lodash", "lodas"}, {"lodash", "lodashx"}, {"lodash", "loadsh"},
		{"commands", "commander"}, {"password", "passport"},
		{"", ""}, {"", "a"}, {"a", ""}, {"abc", "xyz"},
		{"electron", "electorn"}, {"typescript", "typescrpit"},
		{"a-very-long-package-name", "short"},
		{"café", "cafe"}, {"日本語", "日本"},
	}
	for _, p := range pairs {
		for _, maxDist := range []int{1, 2, 3} {
			exact := osaDistance(p[0], p[1])
			got := osaDistanceBounded(p[0], p[1], maxDist)
			if exact <= maxDist {
				if got != exact {
					t.Errorf("osaDistanceBounded(%q,%q,%d) = %d, want exact %d",
						p[0], p[1], maxDist, got, exact)
				}
			} else if got <= maxDist {
				t.Errorf("osaDistanceBounded(%q,%q,%d) = %d, but true distance is %d (must report > %d)",
					p[0], p[1], maxDist, got, exact, maxDist)
			}
		}
	}
}

// FuzzBoundedMatchesExact is a differential fuzz target: it holds the optimized
// implementation against the reference one across arbitrary input, which is the
// only honest way to claim an optimization did not quietly change detection.
func FuzzBoundedMatchesExact(f *testing.F) {
	f.Add("lodash", "lodahs")
	f.Add("express", "expres")
	f.Add("", "")
	f.Add("abc", "abcd")
	f.Add("日本語", "日本")

	f.Fuzz(func(t *testing.T, a, b string) {
		// Keep inputs to a sane size: this is a correctness oracle, not a
		// stress test, and the exact form is O(n*m).
		if len(a) > 64 || len(b) > 64 {
			return
		}
		for maxDist := 1; maxDist <= 3; maxDist++ {
			exact := osaDistance(a, b)
			got := osaDistanceBounded(a, b, maxDist)
			if exact <= maxDist && got != exact {
				t.Fatalf("bounded(%q,%q,%d)=%d disagrees with exact=%d", a, b, maxDist, got, exact)
			}
			if exact > maxDist && got <= maxDist {
				t.Fatalf("bounded(%q,%q,%d)=%d claims within ceiling, exact=%d", a, b, maxDist, got, exact)
			}
		}
	})
}
