package npm

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

// A minimal pnpm-lock.yaml (v9) exercising: importers with runtime + dev groups,
// a scoped package, peer-suffixed snapshot keys/values, and a transitive chain
// (@scope/app -> debug -> ms).
const samplePnpmLock = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: false

importers:

  .:
    dependencies:
      debug:
        specifier: ^4.3.4
        version: 4.3.4(supports-color@8.1.1)
      '@scope/lib':
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      typescript:
        specifier: ^5.4.0
        version: 5.4.0

packages:

  '@scope/lib@1.0.0':
    resolution: {integrity: sha512-aaa}

  debug@4.3.4:
    resolution: {integrity: sha512-bbb}

  ms@2.1.2:
    resolution: {integrity: sha512-ccc}

  typescript@5.4.0:
    resolution: {integrity: sha512-ddd}

snapshots:

  '@scope/lib@1.0.0': {}

  debug@4.3.4(supports-color@8.1.1):
    dependencies:
      ms: 2.1.2

  ms@2.1.2: {}

  typescript@5.4.0: {}
`

func TestParsePnpmLock(t *testing.T) {
	g, err := parsePnpmLock("app/pnpm-lock.yaml", []byte(samplePnpmLock))
	if err != nil {
		t.Fatalf("parsePnpmLock: %v", err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %v, want one synthesized root", g.Roots)
	}
	rootID := g.Roots[0]

	for _, want := range []string{
		"pkg:npm/debug@4.3.4", "pkg:npm/ms@2.1.2", "pkg:npm/typescript@5.4.0",
		"pkg:npm/%40scope/lib@1.0.0", // scoped name, @ encoded in PURL
	} {
		if g.Get(want) == nil {
			t.Errorf("missing node %s", want)
		}
	}

	// Peer suffix stripped: importer version 4.3.4(supports-color@8.1.1) resolves
	// to the bare debug@4.3.4 node as a direct edge.
	if !edgeExists(g, rootID, "pkg:npm/debug@4.3.4") {
		t.Error("missing direct edge root -> debug (peer suffix should be stripped)")
	}
	// Transitive edge from a peer-suffixed snapshot key: debug -> ms.
	if !edgeExists(g, "pkg:npm/debug@4.3.4", "pkg:npm/ms@2.1.2") {
		t.Error("missing transitive edge debug -> ms")
	}
	// ms reached transitively, not a direct root edge.
	if edgeExists(g, rootID, "pkg:npm/ms@2.1.2") {
		t.Error("ms should be transitive, not a direct root edge")
	}
	if d := g.Get("pkg:npm/ms@2.1.2").Depth; d < 2 {
		t.Errorf("ms depth = %d, want >= 2", d)
	}

	// Section tags from importer groups.
	if s := sectionOf(g, "pkg:npm/debug@4.3.4"); s != "runtime" {
		t.Errorf("debug section = %q, want runtime", s)
	}
	if s := sectionOf(g, "pkg:npm/typescript@5.4.0"); s != "dev" {
		t.Errorf("typescript section = %q, want dev", s)
	}

	// Observed provenance.
	if cls, _ := g.Get("pkg:npm/debug@4.3.4").SourceOf(); cls != graph.SourceRegistry {
		t.Errorf("debug source = %q, want registry", cls)
	}
}

func edgeExists(g *graph.Graph, from, to string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Type == graph.EdgeDependsOn {
			return true
		}
	}
	return false
}

func sectionOf(g *graph.Graph, id string) string {
	if n := g.Get(id); n != nil && n.Attr != nil {
		return n.Attr["npm.section"]
	}
	return ""
}
