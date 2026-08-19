package npm

import "testing"

func TestManifestDeclaredDeps(t *testing.T) {
	raw := []byte(`{"name":"app","version":"1.0.0","dependencies":{"@mentra/sdk":"^2.1.29","ws":"^8.16.0"},"devDependencies":{"typescript":"^5.0"}}`)
	g, err := parseManifest("/repo/app/package.json", raw)
	if err != nil {
		t.Fatal(err)
	}
	dd := g.Get(g.Roots[0]).DeclaredDepsOf()
	got := map[string]string{}
	for _, d := range dd {
		got[d.Name] = d.Constraint
	}
	if got["@mentra/sdk"] != "^2.1.29" || got["ws"] != "^8.16.0" {
		t.Errorf("deps = %v", got)
	}
	if _, ok := got["typescript"]; ok {
		t.Error("devDependencies must be excluded")
	}
}

func TestManifestAlias(t *testing.T) {
	raw := []byte(`{"name":"a","version":"1.0.0","dependencies":{"sw-cjs":"npm:string-width@^4.2.0"}}`)
	g, _ := parseManifest("/repo/a/package.json", raw)
	dd := g.Get(g.Roots[0]).DeclaredDepsOf()
	if len(dd) != 1 || dd[0].Name != "string-width" || dd[0].Constraint != "^4.2.0" {
		t.Errorf("alias not resolved in manifest: %+v", dd)
	}
}
