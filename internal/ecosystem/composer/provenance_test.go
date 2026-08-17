package composer

import (
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func TestClassifyPkgSource(t *testing.T) {
	tests := []struct {
		name string
		pkg  composerPkg
		want string
	}{
		{
			name: "packagist zip dist",
			pkg: composerPkg{
				Dist:   composerRef{Type: "zip", URL: "https://api.github.com/repos/o/r/zipball/abc"},
				Source: composerRef{Type: "git", URL: "https://github.com/o/r.git"},
			},
			want: graph.SourceRegistry,
		},
		{
			// dist wins: the zip is what Composer installed and what a feed
			// indexes, even though a git source is also recorded.
			name: "path repository",
			pkg:  composerPkg{Dist: composerRef{Type: "path", URL: "../local-lib"}},
			want: graph.SourcePath,
		},
		{
			name: "git-only package",
			pkg:  composerPkg{Source: composerRef{Type: "git", URL: "https://example.invalid/r.git"}},
			want: graph.SourceGit,
		},
		{
			name: "no dist or source recorded",
			pkg:  composerPkg{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := classifyPkgSource(tt.pkg); got != tt.want {
				t.Errorf("classifyPkgSource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPathRepositoryDegradesCoverage(t *testing.T) {
	lock := []byte(`{
	  "packages": [
	    {"name": "vendor/registry-lib", "version": "1.2.3", "type": "library",
	     "dist": {"type": "zip", "url": "https://api.github.com/repos/vendor/registry-lib/zipball/abc"}},
	    {"name": "acme/local-lib", "version": "0.1.0", "type": "library",
	     "dist": {"type": "path", "url": "../local-lib"}}
	  ],
	  "packages-dev": []
	}`)
	g, err := parseComposerLock("testdata", lock)
	if err != nil {
		t.Fatalf("parseComposerLock: %v", err)
	}
	if class, _ := g.Get("pkg:composer/acme/local-lib@0.1.0").SourceOf(); class != graph.SourcePath {
		t.Errorf("local-lib class = %q, want %q", class, graph.SourcePath)
	}
	if class, _ := g.Get("pkg:composer/vendor/registry-lib@1.2.3").SourceOf(); class != graph.SourceRegistry {
		t.Errorf("registry-lib class = %q, want %q", class, graph.SourceRegistry)
	}
	if cov := g.Coverage(); cov.UnverifiableSources != 1 {
		t.Errorf("UnverifiableSources = %d, want 1", cov.UnverifiableSources)
	}
}
