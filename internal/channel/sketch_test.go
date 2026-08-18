package channel_test

import (
	"fmt"
	"io/fs"
	"testing"

	"ihbv.io/depsnort/internal/channel"
	"ihbv.io/depsnort/internal/channel/npmchan"
	"ihbv.io/depsnort/internal/graph"
)

// The motivating case: a scope redirected to an internal host. Before this
// seam, both nodes carry a bare registry coordinate and graph.Verifiable says
// true for each — the advisory lookup runs against a coordinate the build would
// never have fetched.
func TestScopeRedirectIsRecorded(t *testing.T) {
	files := map[string]string{
		"/repo/.npmrc": "registry=https://registry.npmjs.org/\n" +
			"@acme:registry=https://npm.acme.internal/\n" +
			"//npm.acme.internal/:_authToken=redacted\n",
		"/repo/package.json": `{"overrides":{"minimist":"1.2.8"}}`,
	}
	read := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, fmt.Errorf("open %s: %w", p, fs.ErrNotExist)
	}

	g := graph.New()
	for _, n := range []*graph.Node{
		{ID: "pkg:npm/lodash@4.17.21", Kind: graph.KindPackage, Ecosystem: "npm", Name: "lodash"},
		{ID: "pkg:npm/%40acme/utils@2.0.0", Kind: graph.KindPackage, Ecosystem: "npm", Name: "@acme/utils"},
		{ID: "pkg:npm/minimist@1.2.6", Kind: graph.KindPackage, Ecosystem: "npm", Name: "minimist"},
	} {
		n.SetSource(graph.SourceRegistry, "https://registry.npmjs.org/")
		g.AddNode(n)
	}

	res, err := channel.NewResolver(read, npmchan.Spec{}).Annotate("/repo", g)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("%-28s endpoint=%-22s class=%-9s via=%s sub=%q",
			n.Name, n.Attr[channel.AttrEndpoint], n.Attr[channel.AttrEndpointClass],
			n.Attr[channel.AttrRedirectedBy], n.Attr[channel.AttrSubstitution])
	}
	t.Logf("result: %+v", res)

	if got := g.Get("pkg:npm/%40acme/utils@2.0.0").Attr[channel.AttrEndpointClass]; got != channel.EndpointAlternate {
		t.Errorf("@acme/utils: got %q, want alternate", got)
	}
	if got := g.Get("pkg:npm/lodash@4.17.21").Attr[channel.AttrEndpointClass]; got != channel.EndpointCanonical {
		t.Errorf("lodash: got %q, want canonical", got)
	}
	if res.Substituted != 1 {
		t.Errorf("substituted = %d, want 1", res.Substituted)
	}
}

// Fail-closed: an unreadable config that bears on routing must not default to
// canonical (D-34/D-35).
func TestUnparseableConfigFailsClosed(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if p == "/repo/package.json" {
			return []byte(`{"overrides": TRUNCATED`), nil
		}
		return nil, fs.ErrNotExist
	}
	g := graph.New()
	lodash := &graph.Node{ID: "pkg:npm/lodash@4.17.21", Kind: graph.KindPackage, Ecosystem: "npm", Name: "lodash"}
	lodash.SetSource(graph.SourceRegistry, "https://registry.npmjs.org/")
	g.AddNode(lodash)

	res, _ := channel.NewResolver(read, npmchan.Spec{}).Annotate("/repo", g)
	if got := g.Get("pkg:npm/lodash@4.17.21").Attr[channel.AttrEndpointClass]; got != channel.EndpointUnknown {
		t.Errorf("class = %q, want unknown", got)
	}
	if channel.Attestable(lodash) {
		t.Error("Attestable = true over an unreadable routing config")
	}
	if res.Unknown != 1 || len(res.Gaps) != 1 {
		t.Errorf("unknown=%d gaps=%d, want 1/1", res.Unknown, len(res.Gaps))
	}
}
