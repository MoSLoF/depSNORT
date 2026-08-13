package builtin

import "unicode/utf8"

// osaDistanceBounded is osaDistance with a ceiling. It returns the exact
// distance when that distance is <= maxDist, and some value greater than maxDist
// otherwise — the caller is told "farther than you care about", not how far.
//
// This exists because typosquat detection (VC-006) compares every package name
// against the whole popular-name corpus but only ever acts on distance 1 or 2;
// every other result is computed in full and thrown away. Profiling a
// 1000-package scan put osaDistance at ~71% of the entire check pipeline's CPU
// (Decision D-33).
//
// The win is the length pre-check: two strings whose lengths differ by more than
// maxDist cannot be within maxDist, since every edit changes length by at most
// one. That decides most comparisons without allocating a matrix — or even a
// rune slice, because RuneCountInString does not allocate.
func osaDistanceBounded(a, b string, maxDist int) int {
	la, lb := utf8.RuneCountInString(a), utf8.RuneCountInString(b)
	if d := la - lb; d > maxDist || -d > maxDist {
		return maxDist + 1
	}
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	ra, rb := []rune(a), []rune(b)
	prev2 := make([]int, lb+1)
	prev1 := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev1[j] = j
	}
	prevRowMin := 0

	for i := 1; i <= la; i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			m := min3(prev1[j]+1, cur[j-1]+1, prev1[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := prev2[j-2] + 1; t < m {
					m = t
				}
			}
			cur[j] = m
			if m < rowMin {
				rowMin = m
			}
		}
		// Any alignment path to the final cell must pass through one of two
		// CONSECUTIVE rows: an OSA transposition advances two rows at once, so it
		// can skip a single row but never two. Once both the previous and current
		// rows are entirely above the ceiling, the result cannot come back under
		// it. (Checking one row alone would be unsound for exactly that reason.)
		if i > 1 && rowMin > maxDist && prevRowMin > maxDist {
			return maxDist + 1
		}
		prevRowMin = rowMin
		prev2, prev1, cur = prev1, cur, prev2
	}
	return prev1[lb]
}

// osaDistance computes the Optimal String Alignment distance (Damerau-
// Levenshtein restricted to adjacent transpositions) between a and b. It is the
// metric behind typosquat detection: insertions, deletions, substitutions, and
// adjacent swaps each cost 1. This is the exact, unbounded form; hot paths that
// only care about near matches should use osaDistanceBounded.
func osaDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Three rolling rows: prev2, prev1, cur.
	prev2 := make([]int, lb+1)
	prev1 := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev1[j] = j
	}

	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev1[j] + 1
			ins := cur[j-1] + 1
			sub := prev1[j-1] + cost
			m := min3(del, ins, sub)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := prev2[j-2] + 1; t < m {
					m = t
				}
			}
			cur[j] = m
		}
		prev2, prev1, cur = prev1, cur, prev2
	}
	return prev1[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
