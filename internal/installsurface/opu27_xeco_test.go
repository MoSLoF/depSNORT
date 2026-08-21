package installsurface

import "testing"

// hookByName returns the first hook with the given name, or a zero Hook.
func hookByName(s Surface, name string) Hook {
	for _, h := range s.Hooks {
		if h.Name == name {
			return h
		}
	}
	return Hook{}
}

// TestPartE_NonNpmRunners covers OPU-27 Part E: the package-runner detector fires
// for the non-npm fetch-and-execute runners (Python pipx run / uvx / uv tool run,
// Ruby gem exec, .NET dnx) routed through the REAL per-ecosystem analyzers, and
// stays quiet on the run-an-installed-bin forms (bundle exec, dotnet tool run,
// composer exec, poetry run, python -m) and on offline runners.
func TestPartE_NonNpmRunners(t *testing.T) {
	// --- Python (setup.py), invoked from a shell string (the realistic shape) ---
	pyPositives := map[string]string{
		"pipx run":    `import os; os.system("pipx run evil-tool")`,
		"uvx":         `import os; os.system("uvx evil-tool")`,
		"uv tool run": `import os; os.system("uv tool run evil-tool")`,
	}
	for name, src := range pyPositives {
		h := hookByName(AnalyzePython(src, "", nil), "setup.py:module-level")
		if !h.HasCap(CapNetwork) || !h.HasCap(CapExec) {
			t.Errorf("Python %s: want network+exec, caps=%v", name, h.Caps)
		}
	}
	// Excludes: run an already-installed bin — no fetch, so no runner network.
	for name, src := range map[string]string{
		"poetry run":          `import os; os.system("poetry run pytest")`,
		"python -m":           `import os; os.system("python -m build")`,
		"uvx offline":         `import os; os.system("uvx --offline localtool")`,
		"uv tool run offline": `import os; os.system("uv tool run --offline localtool")`,
	} {
		h := hookByName(AnalyzePython(src, "", nil), "setup.py:module-level")
		if h.HasCap(CapNetwork) {
			t.Errorf("Python %s must not reach the network (no fetch), caps=%v", name, h.Caps)
		}
	}

	// --- Ruby (extconf.rb) ---
	if h := AnalyzeRuby(`system("gem exec evil-gem")`, "", "").Hooks[0]; !h.HasCap(CapNetwork) {
		t.Errorf("Ruby gem exec: want network, caps=%v", h.Caps)
	}
	if h := AnalyzeRuby("`gem exec evil-gem`", "", "").Hooks[0]; !h.HasCap(CapNetwork) {
		t.Errorf("Ruby backtick gem exec: want network, caps=%v", h.Caps)
	}
	// Exclude: bundle exec runs an installed bin.
	if h := AnalyzeRuby(`system("bundle exec rake")`, "", "").Hooks[0]; h.HasCap(CapNetwork) {
		t.Errorf("Ruby bundle exec must not reach the network, caps=%v", h.Caps)
	}

	// --- .NET (install.ps1) ---
	if s := AnalyzeDotNet(map[string]string{"install.ps1": "dnx evil-tool\n"}); !hookByName(s, "install.ps1").HasCap(CapNetwork) {
		t.Errorf(".NET dnx: want network, caps=%v", hookByName(s, "install.ps1").Caps)
	}
	// Exclude: dotnet tool run executes an installed tool.
	if s := AnalyzeDotNet(map[string]string{"install.ps1": "dotnet tool run mytool\n"}); hookByName(s, "install.ps1").HasCap(CapNetwork) {
		t.Errorf(".NET dotnet tool run must not reach the network, caps=%v", hookByName(s, "install.ps1").Caps)
	}
}

// TestPartE_ExfilComposition proves the new non-npm runner network composes into
// the VC-002d exfil substrate: a Ruby extconf.rb that gem-exec-fetches AND reads a
// credential file exhibits network + credentials on one hook (what VC-002d gates on).
func TestPartE_ExfilComposition(t *testing.T) {
	// gem exec supplies the network; the ~/.aws/credentials read supplies creds.
	src := "`gem exec grabber`\nFile.read(File.expand_path('~/.aws/credentials'))\n"
	h := AnalyzeRuby(src, "", "").Hooks[0]
	if !h.HasCap(CapNetwork) || !h.HasCap(CapCredentials) {
		t.Errorf("gem exec + creds read: want network+credentials (VC-002d substrate), caps=%v", h.Caps)
	}
}

// TestPartE_EvidenceLabel confirms a non-npm runner is labeled pkg-runner (network
// reach), distinct from a pkg-install label — the spec's "keep the label accurate"
// discipline (gem exec is a runner; gem install is an install).
func TestPartE_EvidenceLabel(t *testing.T) {
	if !hasEvidence("gem exec evil-gem", "pkg-runner:evil-gem") {
		t.Errorf("gem exec should be labeled pkg-runner; evidence=%v", scanEvidence("gem exec evil-gem"))
	}
	if !hasEvidence("gem install real-gem", "pkg-install:gem install") {
		t.Errorf("gem install should be labeled pkg-install; evidence=%v", scanEvidence("gem install real-gem"))
	}
}
