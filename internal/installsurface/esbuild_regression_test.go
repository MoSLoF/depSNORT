package installsurface

// Regression tests for Decision D-25, driven by a real false positive.
//
// esbuild@0.21.5's install.js is the canonical "sketchy-looking but legitimate"
// installer: it downloads a prebuilt binary and execs it. v0.5.0 flagged it
// VC-002b (with three of four cited URLs scraped from a comment) and VC-002e
// (obfuscation, on a single incidental String.fromCharCode). Both are fixed
// here; the true-positive control proves the fix did not blind the checks.

import (
	"strings"
	"testing"
)

// A faithful reduction of esbuild's install.js: a comment block naming external
// hosts, a real fetch to the npm registry via a variable, a child_process exec
// of the downloaded binary, and one incidental String.fromCharCode.
const esbuildLikeInstallJS = `
var https = require("https");
var child_process = require("child_process");
// The "esbuild" package downloads a prebuilt binary. Some sandboxes block this:
//   - https://snapcraft.io/ (what the Snap Store is)
//   - https://nodejs.org/dist/ (the official version of node)
//   - https://github.com/evanw/esbuild/issues/1711#issuecomment-1027554035
function downloadDirectlyFromNPM(pkg, subpath, binPath) {
  const url = "https://registry.npmjs.org/" + pkg + "/-/" + pkg + ".tgz";
  fetch(url).then(res => writeFileSync(binPath, res));
}
function validate(bin) {
  var stamp = String.fromCharCode(0x2d); // format a single dash for the banner
  return child_process.execFileSync(bin, ["--version"]).toString().trim();
}
`

func analyzeOneHook(t *testing.T, src string) Hook {
	t.Helper()
	s := Analyze(
		map[string]string{"postinstall": "node install.js"},
		func(rel string) ([]byte, bool) {
			if rel == "install.js" {
				return []byte(src), true
			}
			return nil, false
		},
	)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(s.Hooks))
	}
	return s.Hooks[0]
}

func TestEsbuildInstallerNotObfuscated(t *testing.T) {
	h := analyzeOneHookCaps(t, esbuildLikeInstallJS)
	if hasCap(h, CapObfuscation) {
		t.Error("incidental String.fromCharCode must not read as obfuscation (D-25)")
	}
	// The real network capability MUST still be detected — this is a true positive.
	if !hasCap(h, CapNetwork) {
		t.Error("the real fetch() to the npm registry must still register as network")
	}
	if !hasCap(h, CapExec) {
		t.Error("child_process.execFileSync must still register as exec")
	}
}

func TestEsbuildRemotesExcludeCommentURLs(t *testing.T) {
	h := analyzeOneHook(t, esbuildLikeInstallJS)
	var remotes []string
	for _, a := range h.Artifacts {
		if a.Remote {
			remotes = append(remotes, a.Ref)
		}
	}
	for _, r := range remotes {
		if strings.Contains(r, "snapcraft.io") || strings.Contains(r, "nodejs.org") || strings.Contains(r, "github.com") {
			t.Errorf("comment-sourced URL leaked into remotes: %s", r)
		}
	}
	// The genuine target, which lives in code, must survive.
	var sawRegistry bool
	for _, r := range remotes {
		if strings.Contains(r, "registry.npmjs.org") {
			sawRegistry = true
		}
	}
	if !sawRegistry {
		t.Errorf("the real registry URL was lost with the comments; remotes=%v", remotes)
	}
}

// Control: a genuinely obfuscated dropper — char-code ASSEMBLY feeding eval —
// must still trip obfuscation, or the fix would be a blindfold.
func TestCharCodeAssemblyStillDetected(t *testing.T) {
	const dropper = `
var payload = String.fromCharCode(104, 116, 116, 112, 115).toString();
eval(payload);
`
	h := analyzeOneHookCaps(t, dropper)
	if !hasCap(h, CapObfuscation) {
		t.Error("char-code assembly feeding eval must read as obfuscation")
	}
	if !hasCap(h, CapExec) {
		t.Error("eval must read as exec")
	}
}

func analyzeOneHookCaps(t *testing.T, src string) []Capability {
	t.Helper()
	h := analyzeOneHook(t, src)
	caps := append([]Capability(nil), h.Caps...)
	for _, a := range h.Artifacts {
		caps = append(caps, a.Caps...)
	}
	return caps
}
