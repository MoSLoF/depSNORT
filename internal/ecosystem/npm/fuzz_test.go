package npm

import "testing"

// FuzzParseLock drives arbitrary bytes at the package-lock.json parser. depsnort
// parses attacker-supplied lockfiles by design, so a malformed one must produce
// an error — never a panic, and never a nil graph alongside a nil error (D-33).
func FuzzParseLock(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"name":"a","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"a"},"node_modules/b":{"version":"1.0.0"}}}`))
	f.Add([]byte(`{"lockfileVersion":1,"dependencies":{"b":{"version":"1.0.0","requires":{"c":"^1"}}}}`))
	f.Add([]byte(`{"packages":{"node_modules/x":{"version":"1","dependencies":{"y":"1"}}}}`))
	f.Add([]byte(`{"packages":{"../escape":{"version":"1"}}}`))
	f.Add([]byte(`{"dependencies":{"a":{"version":"1","dependencies":{"a":{"version":"2"}}}}}`))
	f.Add([]byte(`{"packages":null,"dependencies":null}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		g, err := parseLock(raw)
		if err != nil {
			return
		}
		if g == nil {
			t.Fatal("nil graph with nil error")
		}
		// Downstream consumers must survive whatever the parser produced.
		_ = g.Coverage()
		_ = g.CountByKind()
		_ = g.Orphans()
		for _, n := range g.SortedNodes() {
			_ = n.ID
		}
	})
}
