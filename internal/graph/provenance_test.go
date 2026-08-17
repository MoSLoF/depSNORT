package graph

import "testing"

func TestClassifyRef(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"", SourceUnknown},
		{"   ", SourceUnknown},
		{"git+https://github.com/o/r.git#abc", SourceGit},
		{"git://github.com/o/r", SourceGit},
		{"git@github.com:o/r.git", SourceGit},
		{"github:owner/repo#semver:^1.0.0", SourceGit},
		{"https://github.com/o/r.git", SourceGit},
		{"file:../local-pkg", SourcePath},
		{"link:../workspace-pkg", SourcePath},
		{"./relative", SourcePath},
		{"/absolute/path", SourcePath},
		{"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", SourceURL},
		{"not a url at all", SourceUnknown},
	}
	for _, tt := range tests {
		if got := ClassifyRef(tt.ref); got != tt.want {
			t.Errorf("ClassifyRef(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}

func TestVerifiableIsRegistryOnly(t *testing.T) {
	if !Verifiable(SourceRegistry) {
		t.Error("a registry source must be verifiable")
	}
	for _, c := range []string{SourceGit, SourcePath, SourceURL, SourceUnknown, ""} {
		if Verifiable(c) {
			t.Errorf("Verifiable(%q) = true; only a registry coordinate is queryable", c)
		}
	}
}

func TestSourceOfDefaultsToUnknown(t *testing.T) {
	n := &Node{ID: "pkg:npm/x@1.0.0", Kind: KindPackage}
	if class, ref := n.SourceOf(); class != SourceUnknown || ref != "" {
		t.Errorf("SourceOf() on a bare node = (%q, %q), want (%q, \"\")", class, ref, SourceUnknown)
	}
	n.SetSource("", "ignored")
	if _, ok := n.Attr[AttrSourceClass]; ok {
		t.Error("SetSource with an empty class must record nothing")
	}
	n.SetSource(SourceGit, "git+https://example.invalid/r.git")
	if class, ref := n.SourceOf(); class != SourceGit || ref == "" {
		t.Errorf("SourceOf() after SetSource = (%q, %q)", class, ref)
	}
}

// TestUnclassifiedNodesDoNotDegradeCoverage is the counterpart to
// TestVerifiableIsRegistryOnly: adapters record a class only on positive
// evidence, so a lockfile format that says nothing about origins must not
// manufacture a scan-wide gap (the D-24 flat-resolution precedent).
func TestUnclassifiedNodesDoNotDegradeCoverage(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "pkg:npm/root@1.0.0", Kind: KindPackage, Ecosystem: "npm", Name: "root"})
	g.MarkRoot("pkg:npm/root@1.0.0")
	dep := g.AddNode(&Node{ID: "pkg:npm/dep@2.0.0", Kind: KindPackage, Ecosystem: "npm", Name: "dep",
		Attr: map[string]string{"npm.path": "node_modules/dep"}})
	g.AddEdge("pkg:npm/root@1.0.0", dep.ID, EdgeDependsOn)

	if cov := g.Coverage(); cov.UnverifiableSources != 0 {
		t.Fatalf("UnverifiableSources = %d for a graph with no recorded provenance, want 0",
			cov.UnverifiableSources)
	}

	dep.SetSource(SourcePath, "file:../dep")
	cov := g.Coverage()
	if cov.UnverifiableSources != 1 {
		t.Fatalf("UnverifiableSources = %d after classifying one path dep, want 1", cov.UnverifiableSources)
	}
	if !cov.Incomplete() {
		t.Error("a path dependency must reach Incomplete(): its OSV lookup proved nothing")
	}
	if len(cov.UnverifiableSourceDetails) != 1 {
		t.Errorf("details = %v, want one entry naming the package", cov.UnverifiableSourceDetails)
	}
}

// TestUnverifiableDetailsAreBounded: the count is never capped, the sample is.
func TestUnverifiableDetailsAreBounded(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "pkg:cargo/root@1.0.0", Kind: KindPackage, Ecosystem: "cargo", Name: "root"})
	g.MarkRoot("pkg:cargo/root@1.0.0")
	for i := range maxUnverifiableDetails * 3 {
		id := "pkg:cargo/vendored" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "@1.0.0"
		n := g.AddNode(&Node{ID: id, Kind: KindPackage, Ecosystem: "cargo", Name: "vendored"})
		n.SetSource(SourcePath, "")
		g.AddEdge("pkg:cargo/root@1.0.0", id, EdgeDependsOn)
	}
	cov := g.Coverage()
	if cov.UnverifiableSources != maxUnverifiableDetails*3 {
		t.Errorf("count = %d, want %d (the count must not be capped)",
			cov.UnverifiableSources, maxUnverifiableDetails*3)
	}
	if len(cov.UnverifiableSourceDetails) != maxUnverifiableDetails {
		t.Errorf("details = %d entries, want the %d-entry cap",
			len(cov.UnverifiableSourceDetails), maxUnverifiableDetails)
	}
}
