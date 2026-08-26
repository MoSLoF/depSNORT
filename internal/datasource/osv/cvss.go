package osv

import (
	"math"
	"strings"
)

// CVSS base-score computation, per the FIRST CVSS v3.1 specification §7.1.
//
// OSV returns severity as a VECTOR STRING ("CVSS:3.1/AV:N/AC:L/…"), not a
// number, so a tool that wants to rank by severity has to score it. The formula
// is published, closed-form and deterministic — no table lookups, no judgement —
// which is what makes it safe to implement here rather than take a dependency
// (D-10). It is verified against reference vectors whose scores FIRST publishes.
//
// v2 and v4 vectors are NOT scored. v2 uses a different formula and v4 replaces
// the closed form with a lookup-table algorithm an order of magnitude larger;
// guessing at either would produce numbers that look authoritative and are not.
// They return ok=false and fall through to the qualitative label.

var (
	cvssAV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAC = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUI = map[string]float64{"N": 0.85, "R": 0.62}
	cvssIm = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	// Privileges Required is the one metric whose weight depends on Scope.
	cvssPRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvssPRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// BaseScore computes the CVSS v3.x base score for a vector string. ok is false
// when the vector is not v3, is malformed, or omits a base metric — never a
// silent zero, because 0.0 is itself a meaningful score (no impact).
func BaseScore(vector string) (float64, bool) {
	v := strings.TrimSpace(strings.ToUpper(vector))
	if !strings.HasPrefix(v, "CVSS:3.0/") && !strings.HasPrefix(v, "CVSS:3.1/") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(v, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}

	scopeChanged := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, false
	}
	pr := cvssPRUnchanged
	if scopeChanged {
		pr = cvssPRChanged
	}
	av, ok1 := cvssAV[m["AV"]]
	ac, ok2 := cvssAC[m["AC"]]
	prv, ok3 := pr[m["PR"]]
	ui, ok4 := cvssUI[m["UI"]]
	c, ok5 := cvssIm[m["C"]]
	i, ok6 := cvssIm[m["I"]]
	a, ok7 := cvssIm[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true // a real score: the vector describes no impact
	}
	exploitability := 8.22 * av * ac * prv * ui
	base := impact + exploitability
	if scopeChanged {
		base = 1.08 * base
	}
	return cvssRoundUp(math.Min(base, 10)), true
}

// cvssRoundUp is the specification's Roundup: the smallest number to one decimal
// place that is >= the input. Plain rounding is NOT the same and produces scores
// that disagree with every published figure.
func cvssRoundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
