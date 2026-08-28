package clojure

import "testing"

// FuzzParseProjectClj drives arbitrary bytes at the project.clj reader — a
// hand-rolled bracket/string scanner over untrusted repo content, the same
// slicing-bug habitat every other manifest parser here fuzzes (D-33). The
// invariants: never panic, never stall, and never emit a dependency whose
// coordinate fails the symbol shape the reader claims to enforce.
func FuzzParseProjectClj(f *testing.F) {
	f.Add([]byte(`(defproject x "1" :dependencies [[a/b "1.0"]])`))
	f.Add([]byte(`(defproject x "1" :dependencies [[a/b "1.0" :exclusions [c/d]] #_[e "2"]])`))
	f.Add([]byte(`:dependencies [[unclosed "1.0"`))
	f.Add([]byte(`:dependencies [ ; comment ]\n[a "1"]]`))
	f.Add([]byte(`:dependencies [["not-a-sym" "1"] [a/b ranged]]`))
	f.Add([]byte("\\; \\[ \\\" :dependencies [[a \"1\"]]"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		deps, _, _, _ := parseProjectClj(string(raw))
		for _, d := range deps {
			if !mavenSymRe.MatchString(d.group) || !mavenSymRe.MatchString(d.artifact) {
				t.Fatalf("coordinate escaped the symbol shape: %q:%q", d.group, d.artifact)
			}
		}
	})
}

// FuzzParseDepsEdn does the same for the deps.edn map reader.
func FuzzParseDepsEdn(f *testing.F) {
	f.Add([]byte(`{:deps {a/b {:mvn/version "1.0"}}}`))
	f.Add([]byte(`{:deps {a/b {:git/url "https://x" :git/sha "s"} c {:local/root "../c"}}}`))
	f.Add([]byte(`{:aliases {:t {:extra-deps {x/y {:mvn/version "2"}}}}}`))
	f.Add([]byte(`{:deps {unclosed {`))
	f.Add([]byte(`{:deps {"str-key" {:mvn/version "1"} #_a/b {:mvn/version "9"}}}`))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		deps, _ := parseDepsEdn(string(raw))
		for _, d := range deps {
			if !mavenSymRe.MatchString(d.group) || !mavenSymRe.MatchString(d.artifact) {
				t.Fatalf("coordinate escaped the symbol shape: %q:%q", d.group, d.artifact)
			}
		}
	})
}
