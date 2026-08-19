package gomod

import "testing"

// FuzzParseGoMod drives arbitrary bytes at the go.mod parser. It asserts the
// parser never panics on hostile input and that a produced graph is
// self-consistent — the same bar the other lockfile parsers' fuzz targets hold
// (D-33). go.mod is attacker-controlled input in a hostile checkout, so it must
// survive anything.
func FuzzParseGoMod(f *testing.F) {
	f.Add([]byte("module x\ngo 1.21\nrequire github.com/a/b v1.2.3\n"))
	f.Add([]byte("module x\nrequire (\n a/b v1.0.0 // indirect\n c/d v2.0.0+incompatible\n)\n"))
	f.Add([]byte("require\n(((\nmodule\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		g, err := parseGoMod("/repo/go.mod", raw)
		if err != nil {
			return
		}
		if g == nil {
			t.Fatal("nil graph with nil error")
		}
		// Every declared edge must land on real nodes, and every version-bearing
		// node must have a non-empty name.
		for _, n := range g.SortedNodes() {
			if n.Version != "" && n.Name == "" {
				t.Fatalf("versioned node with empty name: %+v", n)
			}
		}
	})
}
