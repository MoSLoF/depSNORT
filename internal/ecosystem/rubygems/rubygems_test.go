package rubygems

import (
	"testing"
)

func TestDetect(t *testing.T) {
	a := New()
	if !a.Detect("testdata") {
		t.Error("should detect testdata directory with Gemfile.lock")
	}
	if !a.Detect("testdata/Gemfile.lock") {
		t.Error("should detect testdata/Gemfile.lock directly")
	}
	if a.Detect("testdata/nonexistent") {
		t.Error("should not detect nonexistent path")
	}
}

func TestResolve(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}

	// Expect: root + rails + actioncable + actionpack + nio4r + rack = 6 nodes
	nodes := g.SortedNodes()
	if len(nodes) != 6 {
		for _, n := range nodes {
			t.Logf("  node: %s (depth=%d)", n.ID, n.Depth)
		}
		t.Fatalf("nodes = %d, want 6", len(nodes))
	}

	// Check rails is a direct dependency.
	rails := g.Get("pkg:gem/rails@7.0.4")
	if rails == nil {
		t.Fatal("rails node missing")
	}
	if !rails.Direct {
		t.Error("rails should be direct")
	}

	// Check transitive: rack should be at depth 3 (root -> rails -> actionpack -> rack).
	rack := g.Get("pkg:gem/rack@2.2.8")
	if rack == nil {
		t.Fatal("rack node missing")
	}
	if rack.Depth != 3 {
		t.Errorf("rack depth = %d, want 3", rack.Depth)
	}
}

func TestResolveEdges(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// rails depends on actioncable and actionpack.
	edges := g.SortedEdges()
	railsID := "pkg:gem/rails@7.0.4"
	acID := "pkg:gem/actioncable@7.0.4"
	apID := "pkg:gem/actionpack@7.0.4"

	var railsToAC, railsToAP bool
	for _, e := range edges {
		if e.From == railsID && e.To == acID {
			railsToAC = true
		}
		if e.From == railsID && e.To == apID {
			railsToAP = true
		}
	}
	if !railsToAC {
		t.Error("missing edge: rails -> actioncable")
	}
	if !railsToAP {
		t.Error("missing edge: rails -> actionpack")
	}
}

func TestParseGemSpec(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"rails (7.0.4)", "rails", "7.0.4"},
		{"nio4r (2.5.9)", "nio4r", "2.5.9"},
		{"nokogiri (1.15.4-x86_64-linux)", "nokogiri", "1.15.4-x86_64-linux"},
		{"bad-input", "", ""},
	}
	for _, tt := range tests {
		name, version := parseGemSpec(tt.input)
		if name != tt.wantName || version != tt.wantVersion {
			t.Errorf("parseGemSpec(%q) = (%q, %q), want (%q, %q)",
				tt.input, name, version, tt.wantName, tt.wantVersion)
		}
	}
}
