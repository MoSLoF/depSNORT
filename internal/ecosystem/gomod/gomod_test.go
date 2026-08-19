package gomod

import (
	"testing"

	"ihbv.io/depsnort/internal/purl"
)

func TestParseGoMod(t *testing.T) {
	raw := []byte(`module github.com/sipeed/picoclaw

go 1.25.7

require (
	github.com/google/uuid v1.6.0
	github.com/openai/openai-go/v3 v3.22.0
	golang.org/x/oauth2 v0.35.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require github.com/single/dep v2.0.0+incompatible
`)
	g, err := parseGoMod("/repo/picoclaw/go.mod", raw)
	if err != nil {
		t.Fatal(err)
	}
	root := g.Get(g.Roots[0])
	if root.Name != "github.com/sipeed/picoclaw" {
		t.Errorf("module = %q", root.Name)
	}
	// direct dep
	uuid := g.Get(purl.NewGo("github.com/google/uuid", "v1.6.0").String())
	if uuid == nil || !uuid.Direct {
		t.Errorf("uuid direct node missing/wrong: %+v", uuid)
	}
	// indirect dep
	spew := g.Get(purl.NewGo("github.com/davecgh/go-spew", "v1.1.1").String())
	if spew == nil || spew.Direct {
		t.Errorf("go-spew should be indirect (Direct=false): %+v", spew)
	}
	// major-version suffix kept in the path
	if g.Get(purl.NewGo("github.com/openai/openai-go/v3", "v3.22.0").String()) == nil {
		t.Error("major-version-suffixed module missing")
	}
	// +incompatible tolerated
	if g.Get(purl.NewGo("github.com/single/dep", "v2.0.0+incompatible").String()) == nil {
		t.Error("single-line require with +incompatible missing")
	}
	// flat resolution disclosed
	if root.Attr["depsnort.flat_resolution"] != "gomod" {
		t.Error("go.mod flat resolution not disclosed")
	}
	// count: root + 6 requires
	pk := 0
	for _, n := range g.SortedNodes() {
		if n.Kind == "" || n.Kind == "package" {
			pk++
		}
	}
	if pk != 7 {
		t.Errorf("nodes = %d, want 7 (root + 6)", pk)
	}
}

func TestDetect(t *testing.T) {
	if (&Adapter{}).Name() != "gomod" {
		t.Error("name")
	}
}
