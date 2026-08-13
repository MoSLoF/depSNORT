package nuget

import "testing"

// FuzzParsePackagesLock drives arbitrary bytes at the packages.lock.json parser,
// whose schema nests target-framework -> package -> resolved/dependencies.
func FuzzParsePackagesLock(f *testing.F) {
	f.Add([]byte(`{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.3"}}}}`))
	f.Add([]byte(`{"version":1,"dependencies":{"net8.0":{"A":{"type":"Transitive","resolved":"1.0.0","dependencies":{"B":"2.0.0"}}}}}`))
	f.Add([]byte(`{"dependencies":{"":{"":{}}}}`))
	f.Add([]byte(`{"dependencies":null}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		g, err := parsePackagesLock("packages.lock.json", raw)
		if err != nil {
			return
		}
		if g == nil {
			t.Fatal("nil graph with nil error")
		}
		_ = g.Coverage()
		_ = g.Orphans()
	})
}
