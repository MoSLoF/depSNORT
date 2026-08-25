package npm

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestExtractInstallSurfaceBuildsSubgraph(t *testing.T) {
	a := &Adapter{}
	g, err := a.Resolve("testdata/wormy")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/wormy", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	counts := g.CountByKind()
	if counts[graph.KindInstallHook] < 2 {
		t.Errorf("install-hook nodes = %d, want >=2", counts[graph.KindInstallHook])
	}
	if counts[graph.KindReferencedArtifact] == 0 {
		t.Error("expected referenced-artifact nodes")
	}
	if counts[graph.KindSink] == 0 {
		t.Error("expected sink nodes")
	}

	// The evil package's hook must exist and carry the damning capabilities.
	hook := g.Get("hook:pkg:npm/depsnort-fixture-evil@1.0.0#preinstall")
	if hook == nil {
		t.Fatal("missing preinstall hook node for depsnort-fixture-evil")
	}
	for _, cap := range []string{"cap.network", "cap.credentials", "cap.exec", "cap.obfuscation"} {
		if hook.Attr[cap] != "true" && !artifactHasCap(g, hook.ID, cap) {
			t.Errorf("depsnort-fixture-evil hook chain missing %s", cap)
		}
	}

	// Edge types must be present so the dual-tree renders.
	var declares, execs, fetches, reads int
	for _, e := range g.Edges {
		switch e.Type {
		case graph.EdgeDeclaresHook:
			declares++
		case graph.EdgeHookExecs:
			execs++
		case graph.EdgeHookFetches:
			fetches++
		case graph.EdgeHookReadsEnv:
			reads++
		}
	}
	if declares < 2 || execs < 1 || fetches < 1 || reads < 1 {
		t.Errorf("edges declares=%d execs=%d fetches=%d reads=%d", declares, execs, fetches, reads)
	}

	// The benign native-build package must NOT gain a credentials capability.
	nativeHook := g.Get("hook:pkg:npm/depsnort-fixture-native@2.0.0#install")
	if nativeHook == nil {
		t.Fatal("missing install hook node for depsnort-fixture-native")
	}
	if nativeHook.Attr["cap.credentials"] == "true" {
		t.Error("benign native-build hook wrongly marked as touching credentials")
	}
}

// artifactHasCap reports whether any artifact reachable from hookID has cap.
func artifactHasCap(g *graph.Graph, hookID, cap string) bool {
	for _, e := range g.Edges {
		if e.From != hookID {
			continue
		}
		if n := g.Get(e.To); n != nil && n.Attr[cap] == "true" {
			return true
		}
	}
	return false
}

// TestExtractInstallSurfaceProjectRootAIAgentConfigRelativePath is a review-
// found regression (OPU-37): the project-root AI-agent config scan built its
// candidate read path by joining installsurface.AIAgentConfigFiles onto the
// adapter's `root` variable directly, rather than the already-computed
// absolute reader.Root(). Every OTHER call site in ExtractInstallSurface
// builds an absolute path first (see pkgDir/absPkgDir above) specifically
// because securefs.Reader.ReadFile re-joins a relative argument onto its own
// absolute root — so passing a relative root back in doubles the directory
// component and the read silently fails. This test calls Resolve/
// ExtractInstallSurface with a RELATIVE testdata path — "testdata/
// aiagentconfig", mirroring every other test in this file (e.g.
// TestExtractInstallSurfaceBuildsSubgraph's "testdata/wormy") — which is
// exactly the invocation shape that went silently blind: it passed with an
// absolute path or the bare "." (where filepath.Join happens to strip the
// leading "." and the bug is invisible) and produced zero findings for any
// other relative directory name, including this one.
func TestExtractInstallSurfaceProjectRootAIAgentConfigRelativePath(t *testing.T) {
	a := &Adapter{}
	g, err := a.Resolve("testdata/aiagentconfig")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/aiagentconfig", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}
	if got := g.CountByKind()[graph.KindInstallHook]; got == 0 {
		t.Fatal("expected a hook node from the project-root .vscode/tasks.json scan, got none — " +
			"the project-root AI-agent config scan did not fire for a relative scan path")
	}
}

func TestExtractInstallSurfaceNoNodeModulesIsQuiet(t *testing.T) {
	a := &Adapter{}
	g, err := a.Resolve("testdata/proj") // fixture has no node_modules on disk
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ExtractInstallSurface("testdata/proj", g); err != nil {
		t.Fatalf("expected quiet skip, got %v", err)
	}
	if g.CountByKind()[graph.KindInstallHook] != 0 {
		t.Error("no node_modules present: expected zero hook nodes, not invented ones")
	}
}
