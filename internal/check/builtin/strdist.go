package builtin

// osaDistance computes the Optimal String Alignment distance (Damerau-
// Levenshtein restricted to adjacent transpositions) between a and b. It is the
// metric behind typosquat detection: insertions, deletions, substitutions, and
// adjacent swaps each cost 1. Bounded early-exit keeps it cheap for the short
// strings (package names) we compare.
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
