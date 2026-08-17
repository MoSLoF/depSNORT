package builtin

import (
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/finding"
	"ihbv.io/depsnort/internal/graph"
)

// sourceGraph builds a root plus one dependency carrying the given provenance.
func sourceGraph(class, ref string) (*graph.Graph, *graph.Node) {
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:cargo/app@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "cargo", Name: "app", Version: "1.0.0"})
	g.MarkRoot(root.ID)
	dep := g.AddNode(&graph.Node{ID: "pkg:cargo/vendored-fork@0.9.6", Kind: graph.KindPackage,
		Ecosystem: "cargo", Name: "vendored-fork", Version: "0.9.6"})
	dep.SetSource(class, ref)
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)
	return g, dep
}

func TestVC009RegistrySourceIsSilent(t *testing.T) {
	g, _ := sourceGraph(graph.SourceRegistry, "registry+https://github.com/rust-lang/crates.io-index")
	if fs := (UnverifiableSource{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("VC-009 fired on a registry package: %+v", fs)
	}
}

// TestVC009UnclassifiedIsSilent: a lockfile format that records no origin must
// not produce a finding. Absence of evidence is not evidence of a fork (D-41).
func TestVC009UnclassifiedIsSilent(t *testing.T) {
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:npm/app@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "npm", Name: "app", Version: "1.0.0"})
	g.MarkRoot(root.ID)
	dep := g.AddNode(&graph.Node{ID: "pkg:npm/old-dep@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "npm", Name: "old-dep", Version: "1.0.0"})
	g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)

	if fs := (UnverifiableSource{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("VC-009 fired on a package with no recorded provenance: %+v", fs)
	}
}

func TestVC009RootIsNeverFlagged(t *testing.T) {
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:cargo/app@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "cargo", Name: "app", Version: "1.0.0"})
	root.SetSource(graph.SourcePath, "")
	g.MarkRoot(root.ID)

	if fs := (UnverifiableSource{}).Run(&check.Context{Graph: g}); len(fs) != 0 {
		t.Errorf("VC-009 flagged the project being scanned: %+v", fs)
	}
}

// TestVC009VendoredIsAdvisoryAlone is the posture the field report argued for:
// vendoring is often STRONGER than a git dependency, so it must surface without
// gating.
func TestVC009VendoredIsAdvisoryAlone(t *testing.T) {
	g, _ := sourceGraph(graph.SourcePath, "")
	fs := (UnverifiableSource{}).Run(&check.Context{Graph: g})
	if len(fs) != 1 {
		t.Fatalf("VC-009 findings = %d, want 1", len(fs))
	}
	f := fs[0]
	if f.GateClass != finding.GateAdvisory {
		t.Errorf("gate class = %q, want advisory: vendoring alone is not a risk", f.GateClass)
	}
	if f.Axis != finding.AxisHygiene {
		t.Errorf("axis = %q, want hygiene", f.Axis)
	}
	// The finding must say WHY it exists — that the advisory pass could not
	// speak to this package — not merely that a package is vendored.
	if !strings.Contains(f.Evidence, "no registry coordinate") {
		t.Errorf("evidence does not explain the coverage consequence: %q", f.Evidence)
	}
	if !strings.Contains(f.Remediation, "upstream") {
		t.Errorf("remediation should point at the upstream diff, got %q", f.Remediation)
	}
}

// TestVC009EscalatesWithInstallCode: the composed shape — an upstream that can
// change under a pin AND a mechanism that runs on install.
func TestVC009EscalatesWithInstallCode(t *testing.T) {
	g, dep := sourceGraph(graph.SourceGit, "git+https://example.invalid/fork.git#9f1c0de")
	hook := g.AddNode(&graph.Node{ID: "hook:" + dep.ID + "#build.rs", Kind: graph.KindInstallHook,
		Ecosystem: "cargo", Name: "build.rs"})
	g.AddEdge(dep.ID, hook.ID, graph.EdgeDeclaresHook)

	fs := (UnverifiableSource{}).Run(&check.Context{Graph: g})
	if len(fs) != 1 {
		t.Fatalf("VC-009 findings = %d, want 1", len(fs))
	}
	f := fs[0]
	if f.GateClass != finding.GateEligible {
		t.Errorf("gate class = %q, want gate-eligible when install-time code is also present", f.GateClass)
	}
	if f.Severity != finding.SevMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if !strings.Contains(f.Evidence, "executes on install") {
		t.Errorf("evidence should name the composition, got %q", f.Evidence)
	}
	// The git URL must reach the report: a finding that cannot name what it
	// could not verify is barely better than a count.
	if !strings.Contains(f.Evidence, "example.invalid") {
		t.Errorf("evidence does not name the source, got %q", f.Evidence)
	}
}

func TestVC009RemediationFitsTheClass(t *testing.T) {
	cases := map[string]string{
		graph.SourceGit:  "immutable commit",
		graph.SourcePath: "review the vendored source",
		graph.SourceURL:  "checksum",
	}
	for class, want := range cases {
		g, _ := sourceGraph(class, "ref")
		fs := (UnverifiableSource{}).Run(&check.Context{Graph: g})
		if len(fs) != 1 {
			t.Fatalf("%s: findings = %d, want 1", class, len(fs))
		}
		if !strings.Contains(fs[0].Remediation, want) {
			t.Errorf("%s remediation = %q, want it to mention %q", class, fs[0].Remediation, want)
		}
	}
}
