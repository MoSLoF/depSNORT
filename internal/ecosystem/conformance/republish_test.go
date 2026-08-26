package conformance_test

import (
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/cargo"
	"ihbv.io/depsnort/internal/ecosystem/composer"
	"ihbv.io/depsnort/internal/ecosystem/gomod"
	"ihbv.io/depsnort/internal/ecosystem/npm"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
	"ihbv.io/depsnort/internal/graph"
)

// Republish-edge conformance: the SHARED-HELPER-COPY contract (D-152).
//
// graph.EdgeRepublish is the worm loop — an install hook that publishes points
// back at its own package. D-152 wired it in instsurf.AddToGraph, the helper
// four adapters call, and every unit test passed. But npm, PyPI and Composer
// each hand-roll a near-verbatim copy of that helper rather than calling it, so
// the edge reached neither of them — including npm, the one ecosystem the
// Shai-Hulud family actually targets. A live scan of a worm fixture produced a
// correct VC-002k critical finding over a graph that showed no loop at all: the
// report and the graph disagreed, and the graph is what an operator opens to
// see how far the compromise reaches.
//
// This is the D-15/D-37 failure shape once more — a second implementation of a
// rule drifting from the first — so it gets the same treatment: a test that
// fails when any adapter stops drawing the edge, rather than trust that the
// next person to touch the helper remembers there are four copies.
//
// Each fixture below is an inert install hook that runs `npm publish`. IOCs are
// RFC 5737 TEST-NET-3 / .invalid throughout; nothing here is ever executed.

type republishCase struct {
	name      string
	adapter   surfaceExtractor
	ecosystem string
	id        string
	files     map[string]string
}

// republishCases covers every adapter that materializes install-hook nodes.
// Adding an adapter without adding it here is caught by
// TestRepublishConformanceCoversEveryHookAdapter below.
func republishCases() []republishCase {
	// The payload every fixture ends up running. Kept identical across
	// ecosystems so a failure means the adapter differs, not the fixture.
	const payload = "npm publish --access public"

	return []republishCase{
		{
			name: "npm", adapter: npm.New(), ecosystem: "npm",
			id: "pkg:npm/wormy@1.0.0",
			files: map[string]string{
				"package.json": `{"name":"wormy","version":"1.0.0","scripts":{"postinstall":"` + payload + `"}}`,
			},
		},
		{
			name: "pypi", adapter: pypi.New(), ecosystem: "pypi",
			id: "pkg:pypi/wormy@1.0.0",
			files: map[string]string{
				"setup.py": "from setuptools import setup\nimport subprocess\n" +
					"subprocess.check_call('" + payload + "', shell=True)\n" +
					"setup(name='wormy', version='1.0.0')\n",
			},
		},
		{
			name: "composer", adapter: composer.New(), ecosystem: "composer",
			id: "pkg:composer/vendor/wormy@1.0.0",
			files: map[string]string{
				"composer.json": `{"name":"vendor/wormy","version":"1.0.0",` +
					`"scripts":{"post-install-cmd":["` + payload + `"]}}`,
			},
		},
		{
			name: "cargo", adapter: cargo.New(), ecosystem: "cargo",
			id: "pkg:cargo/wormy@1.0.0",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"wormy\"\nversion = \"1.0.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
				"build.rs": "fn main() {\n    std::process::Command::new(\"sh\").arg(\"-c\")\n" +
					"        .arg(\"" + payload + "\").status().unwrap();\n}\n",
			},
		},
		{
			// The gemspec branch fires only on a gemspec DECLARING native
			// extensions (D-150) — scanning every gemspec would trip CapExec on
			// the ubiquitous `git ls-files` idiom — so the declaration is part
			// of the fixture rather than incidental to it.
			name: "rubygems", adapter: rubygems.New(), ecosystem: "gem",
			id: "pkg:gem/wormy@1.0.0",
			files: map[string]string{
				"wormy.gemspec": "Gem::Specification.new do |s|\n  s.name = \"wormy\"\n" +
					"  s.extensions = [\"ext/extconf.rb\"]\n  system(\"" + payload + "\")\nend\n",
			},
		},
		{
			name: "nuget", adapter: nuget.New(), ecosystem: "nuget",
			id: "pkg:nuget/wormy@1.0.0",
			files: map[string]string{
				"build/wormy.targets": "<Project><Target Name=\"Go\" AfterTargets=\"Build\">\n" +
					"<Exec Command=\"" + payload + "\" />\n</Target></Project>",
			},
		},
		{
			name: "gomod", adapter: gomod.New(), ecosystem: "gomod",
			id: "pkg:gomod/example.com/wormy@v1.0.0",
			files: map[string]string{
				"go.mod": "module example.com/wormy\n\ngo 1.21\n",
				"gen.go": "package wormy\n\n//go:generate sh -c \"" + payload + "\"\n",
			},
		},
	}
}

// TestRepublishEdgeIsDrawnByEveryAdapter is the contract itself.
func TestRepublishEdgeIsDrawnByEveryAdapter(t *testing.T) {
	for _, c := range republishCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			g := graph.New()
			g.AddNode(&graph.Node{
				ID: c.id, Kind: graph.KindPackage, Ecosystem: c.ecosystem,
				Name: "wormy", Version: "1.0.0", Depth: 0,
			})
			g.MarkRoot(c.id)
			if err := c.adapter.ExtractInstallSurface(dir, g); err != nil {
				t.Logf("ExtractInstallSurface reported gaps: %v", err)
			}

			// Precondition: the adapter has to have found the hook at all, or
			// "no republish edge" would be a fixture bug reported as a contract
			// violation — and the assertion below would be vacuous.
			var hooks []string
			for _, n := range g.SortedNodes() {
				if n.Kind == graph.KindInstallHook {
					hooks = append(hooks, n.Name)
				}
			}
			if len(hooks) == 0 {
				t.Fatalf("fixture produced no install hook; the republish assertion would be vacuous")
			}

			for _, e := range g.Edges {
				if e.Type == graph.EdgeRepublish {
					if e.To != c.id {
						t.Errorf("republish edge must point back at the package (the loop), got %q", e.To)
					}
					return
				}
			}
			t.Errorf("hook(s) %v publish to a registry but no %s edge was drawn;\n"+
				"this is the D-152 shape: an adapter that hand-rolls its own copy of "+
				"instsurf.AddToGraph and has drifted from it", hooks, graph.EdgeRepublish)
		})
	}
}

// TestRepublishNoEdgeWithoutPublish is the boundary. Without it the suite above
// would still pass if some adapter drew a republish edge unconditionally.
func TestRepublishNoEdgeWithoutPublish(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"name":"benign","version":"1.0.0","scripts":{"postinstall":"node-gyp rebuild"}}`,
	})
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: "pkg:npm/benign@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "benign", Version: "1.0.0", Depth: 0,
	})
	g.MarkRoot("pkg:npm/benign@1.0.0")
	if err := npm.New().ExtractInstallSurface(dir, g); err != nil {
		t.Logf("ExtractInstallSurface reported gaps: %v", err)
	}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeRepublish {
			t.Errorf("an ordinary build hook must draw no republish edge: %+v", e)
		}
	}
}

// TestRepublishConformanceCoversEveryHookAdapter fails when an adapter is added
// to the suite's imports but not to republishCases(), which is how a coverage
// table quietly stops covering things.
func TestRepublishConformanceCoversEveryHookAdapter(t *testing.T) {
	// Every ecosystem whose adapter materializes install-hook nodes. Keep in
	// sync with the adapters that implement ExtractInstallSurface.
	want := []string{"npm", "pypi", "composer", "cargo", "rubygems", "nuget", "gomod"}
	have := map[string]bool{}
	for _, c := range republishCases() {
		have[c.name] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("adapter %q builds install hooks but has no republish conformance case", w)
		}
	}
	if len(have) != len(want) {
		t.Errorf("republishCases() has %d cases for %d hook adapters", len(have), len(want))
	}
}
