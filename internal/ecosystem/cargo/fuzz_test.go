package cargo

import "testing"

// FuzzParseCargoLock drives arbitrary bytes at the Cargo.lock reader. This one
// is a hand-rolled line scanner rather than a TOML library (Decision D-10, no
// third-party dependencies), which makes it precisely the parser most likely to
// mishandle a malformed table, an unterminated string, or a stray bracket — so
// it is the one that most needs fuzzing (D-33).
func FuzzParseCargoLock(f *testing.F) {
	f.Add([]byte("[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n"))
	f.Add([]byte("[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n \"b 1.0.0\",\n]\n"))
	f.Add([]byte("version = 3\n\n[[package]]\nname = \"x\"\n"))
	f.Add([]byte("[[package]]\nname = \"unterminated\n"))
	f.Add([]byte("[[package]]\ndependencies = [\n"))
	f.Add([]byte("[[package]]\nname=\"a\"\nversion=\"1\"\n[[package]]\nname=\"a\"\nversion=\"2\"\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		g, err := parseCargoLock("Cargo.lock", raw)
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
