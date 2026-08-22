package installsurface

import (
	"sort"
	"strings"
	"testing"
)

// probeCaps runs AnalyzePython on a setup.py snippet and returns the union of
// capabilities across its hooks, sorted.
func probeCaps(setupPy string) []string {
	s := AnalyzePython(setupPy, "", nil)
	set := map[string]bool{}
	for _, h := range s.Hooks {
		for _, c := range h.Caps {
			set[string(c)] = true
		}
	}
	var out []string
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// TestOPU19InstallSurfaceProbeTable freezes the A.I.G cross-map coverage table
// (OPU-19): each install-surface pattern maps to an exact capability set, so the
// coverage map cannot silently regress. It is the proven Part A/Part B output —
// authorized_keys/systemctl/launchctl/getfqdn/getsockname now fire, and an IMDS
// endpoint reached via a URL raises `credentials` (not just `network`) because
// imdsRe reads the raw source before the URL strip.
func TestOPU19InstallSurfaceProbeTable(t *testing.T) {
	table := []struct {
		name    string
		setupPy string
		want    []string
	}{
		// decode → exec: VC-002e (already covered; guards against regression).
		{"decode-exec", "import base64\nexec(base64.b64decode('aGVsbG8='))\n", []string{"exec", "obfuscation"}},
		// ssh private key read: VC-002c/d (already covered).
		{"ssh-id_rsa", "open('/root/.ssh/id_rsa').read()\n", []string{"credentials"}},
		// authorized_keys implant: Part A — was invisible, now credentials.
		{"authorized_keys", "open('/root/.ssh/authorized_keys','a').write(k)\n", []string{"credentials"}},
		// IMDS via URL: Part B — was network-only, now credentials+network (→ VC-002d).
		{"imds-url-aws", "from urllib.request import urlopen\nurlopen('http://169.254.169.254/latest/meta-data/iam/security-credentials/')\n", []string{"credentials", "network"}},
		{"imds-url-gcp", "import requests\nrequests.get('http://metadata.google.internal/computeMetadata/v1/')\n", []string{"credentials", "network"}},
		// persistence mechanisms: exec + filesystem (VC-002g gates on the marker).
		{"crontab", "import subprocess\nsubprocess.run(['crontab','-'])\n", []string{"exec", "filesystem"}},
		{"systemctl", "import os\nos.system('systemctl enable evil')\n", []string{"exec", "filesystem"}},
		{"launchctl", "import os\nos.system('launchctl load x.plist')\n", []string{"exec", "filesystem"}},
		// recon: env only — deliberately NOT a standalone finding (Part D).
		{"gethostname", "import socket\nsocket.gethostname()\n", []string{"env"}},
		{"getfqdn", "import socket\nsocket.getfqdn()\n", []string{"env"}}, // Part A: was none.
		{"getsockname", "sock.getsockname()\n", []string{"env"}},          // Part A: was none.
		// benign install write: filesystem, but NOT a persistence marker (VC-002g stays silent).
		{"benign-pth", "import site\nopen(site.getsitepackages()[0]+'/x.pth','w')\n", []string{"filesystem"}},
	}
	for _, tc := range table {
		got := probeCaps(tc.setupPy)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: caps = [%s], want [%s]", tc.name, strings.Join(got, " "), strings.Join(tc.want, " "))
		}
	}
}

// TestOPU19PersistenceMarkerSplit pins the persistence/benign split: a persistence
// location is a persistence marker, an ordinary install write is not — the gate
// VC-002g reads. If a marker moved to the wrong list, VC-002g would either miss a
// real persistence write or false-positive on site-packages.
func TestOPU19PersistenceMarkerSplit(t *testing.T) {
	persistence := []string{"crontab", "systemd", "systemctl", "launchctl", "launchd", "startup-folder", ".bashrc", ".zshrc", ".profile", "/etc/", "$PROFILE"}
	for _, m := range persistence {
		if !IsPersistenceMarker(m) {
			t.Errorf("%q should be a persistence marker", m)
		}
	}
	benign := []string{"site-packages", ".pth", "Gem.dir", "os.homedir()", "sysconfig.", "AppData\\Roaming", "startup", "process_startup"}
	for _, m := range benign {
		if IsPersistenceMarker(m) {
			t.Errorf("%q must NOT be a persistence marker (ordinary install write)", m)
		}
	}
}
