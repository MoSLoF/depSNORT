package npm

import (
	"fmt"
	"strings"
	"testing"
)

// genLock builds a synthetic package-lock.json with n packages, each depending
// on the next few. The committed fixtures are deliberately small; a performance
// baseline taken against a 69-line lockfile measures nothing a real monorepo
// would recognize (D-33).
func genLock(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"name":"bench","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"bench","version":"1.0.0","dependencies":{"dep0":"1.0.0"}}`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `,"node_modules/dep%d":{"version":"1.0.%d","resolved":"https://registry.npmjs.org/dep%d/-/dep%d-1.0.%d.tgz","integrity":"sha512-%040d"`,
			i, i%50, i, i, i%50, i)
		// Fan out to the next three packages so the graph has real edges.
		if i+3 < n {
			fmt.Fprintf(&b, `,"dependencies":{"dep%d":"1.0.0","dep%d":"1.0.0","dep%d":"1.0.0"}`, i+1, i+2, i+3)
		}
		if i%17 == 0 {
			b.WriteString(`,"hasInstallScript":true`)
		}
		b.WriteString(`}`)
	}
	b.WriteString(`}}`)
	return []byte(b.String())
}

func benchParse(b *testing.B, n int) {
	raw := genLock(n)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g, err := parseLock(raw)
		if err != nil {
			b.Fatal(err)
		}
		if g.Len() == 0 {
			b.Fatal("empty graph")
		}
	}
}

func BenchmarkParseLock100(b *testing.B)  { benchParse(b, 100) }
func BenchmarkParseLock1000(b *testing.B) { benchParse(b, 1000) }
func BenchmarkParseLock5000(b *testing.B) { benchParse(b, 5000) }

// Coverage is computed on every scan and walks every node, so it sits on the hot
// path for large workspaces.
func BenchmarkCoverage1000(b *testing.B) {
	g, err := parseLock(genLock(1000))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Coverage()
	}
}
