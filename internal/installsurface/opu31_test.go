package installsurface

import "testing"

// OPU-31: load-time (import-time) execution analysis of npm entry modules.

func evidenceHas(ev []string, marker string) bool {
	for _, e := range ev {
		if e == marker {
			return true
		}
	}
	return false
}

// An entry module that spawns a process at import is a load-time execution
// surface even though the package declares no lifecycle script.
func TestAnalyzeLoadTimeFiresOnEntryExec(t *testing.T) {
	src := `export { fmt } from './helpers.mjs';
import { spawn } from 'node:child_process';
spawn('/bin/true', { detached: true });`
	s := AnalyzeLoadTime("dist/index.mjs", src, func(string) ([]byte, bool) { return nil, false })
	if len(s.Hooks) != 1 {
		t.Fatalf("want 1 load-time hook, got %d", len(s.Hooks))
	}
	h := s.Hooks[0]
	if !h.HasCap(CapExec) {
		t.Error("entry with child_process must register CapExec")
	}
	if !evidenceHas(h.Evidence, "load-time-execution") {
		t.Errorf("want load-time-execution evidence, got %v", h.Evidence)
	}
	if h.Name != "module-load:dist/index.mjs" {
		t.Errorf("hook name = %q", h.Name)
	}
}

// A pure data/helper entry module (no execution capability) is NOT a load-time
// surface and must yield no hook — this is the specificity guard.
func TestAnalyzeLoadTimePureDataEntrySilent(t *testing.T) {
	src := `export function fmt(x){ return String(x); }
export const VERSION = '1.0.0';`
	s := AnalyzeLoadTime("index.js", src, nil)
	if len(s.Hooks) != 0 {
		t.Fatalf("pure-data entry must yield no hook, got %d", len(s.Hooks))
	}
}

// A referenced sibling carrying native-executable magic is surfaced as the
// bundled-binary payload — the composition VC-002j escalates.
func TestAnalyzeLoadTimeBundledNativeBinary(t *testing.T) {
	src := `import { spawn } from 'node:child_process';
const b = new URL('./math-core.bin', import.meta.url);
spawn(b, { detached: true });`
	read := func(rel string) ([]byte, bool) {
		if rel == "dist/math-core.bin" {
			return []byte("\x7fELF\x02\x01\x01\x00rest-is-benign"), true
		}
		return nil, false
	}
	s := AnalyzeLoadTime("dist/index.mjs", src, read)
	if len(s.Hooks) != 1 {
		t.Fatalf("want 1 hook, got %d", len(s.Hooks))
	}
	h := s.Hooks[0]
	if !evidenceHas(h.Evidence, "bundled-native-executable:elf") {
		t.Errorf("want bundled-native-executable:elf on hook, got %v", h.Evidence)
	}
	var sawArt bool
	for _, a := range h.Artifacts {
		if a.Ref == "math-core.bin" {
			sawArt = true
			var execCap bool
			for _, c := range a.Caps {
				if c == CapExec {
					execCap = true
				}
			}
			if !execCap {
				t.Error("bundled-binary artifact must carry CapExec")
			}
		}
	}
	if !sawArt {
		t.Errorf("bundled-binary artifact not recorded; artifacts=%+v", h.Artifacts)
	}
}

func TestNativeExecutableKind(t *testing.T) {
	cases := []struct {
		name   string
		b      []byte
		kind   string
		native bool
	}{
		{"elf", []byte("\x7fELF\x02\x01"), "elf", true},
		{"pe", []byte("MZ\x90\x00"), "pe", true},
		{"macho-thin-le", []byte{0xcf, 0xfa, 0xed, 0xfe}, "mach-o", true},
		{"macho-fat", []byte{0xca, 0xfe, 0xba, 0xbe}, "mach-o", true},
		{"js-text", []byte("import x from 'y'"), "", false},
		{"too-short", []byte{0x7f, 0x45}, "", false},
	}
	for _, c := range cases {
		k, ok := nativeExecutableKind(c.b)
		if ok != c.native || k != c.kind {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", c.name, k, ok, c.kind, c.native)
		}
	}
}
