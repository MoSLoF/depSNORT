package osv

import "testing"

// The oracle: vectors whose base scores FIRST publishes. If the implementation
// disagrees with any of these it is wrong, regardless of how reasonable the
// arithmetic looks.
func TestBaseScoreMatchesPublishedVectors(t *testing.T) {
	for _, tc := range []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		// Scope-Changed WITH privileges required: the only shape that tells the
		// two PR weight tables apart, since PR:N weighs 0.85 in both.
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	} {
		got, ok := BaseScore(tc.vector)
		if !ok {
			t.Errorf("%s: not scored", tc.vector)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %.1f, want %.1f", tc.vector, got, tc.want)
		}
	}
}

func TestBaseScoreRefusesWhatItCannotScore(t *testing.T) {
	for _, v := range []string{
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",              // v2: different formula
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", // v4: table-driven
		// A v3 body under a v2 header. Every other guard passes it; only the
		// version prefix stops the tool reporting a v3 score for a v2 vector.
		"CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",     // no Scope
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bad metric value
		"", "garbage", "CVSS:3.1/",
	} {
		if score, ok := BaseScore(v); ok {
			t.Errorf("%q should not be scored, got %.1f", v, score)
		}
	}
}

// A zero score is a real answer, not an absence — the distinction the ok return
// exists for.
func TestBaseScoreZeroIsReported(t *testing.T) {
	got, ok := BaseScore("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
	if !ok || got != 0 {
		t.Errorf("a no-impact vector scores 0.0 and is scored; got %.1f ok=%v", got, ok)
	}
}
