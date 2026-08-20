package expand_test

import (
	"context"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/datasource"
	"ihbv.io/depsnort/internal/expand"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/semver"
)

// fakePyPI is a Declarer over a fixed metadata table, and a Presumer over
// semver-ish ">=" / "==" constraints. Absent key = never read.
type fakePyPI struct {
	table    map[string][]expand.Declaration
	versions map[string][]string
}

func (*fakePyPI) Ecosystem() string { return "pypi" }

// Identify folds per PEP 503 — the leak D-15 found: without it,
// Flask_SQLAlchemy and flask-sqlalchemy become two nodes.
func (*fakePyPI) Identify(name, version string) (string, string) {
	canon := strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name))
	for strings.Contains(canon, "--") {
		canon = strings.ReplaceAll(canon, "--", "-")
	}
	if canon == "" {
		return "", ""
	}
	id := "pkg:pypi/" + canon
	if version != "" {
		id += "@" + version
	}
	return id, canon
}

func (f *fakePyPI) Declared(_ context.Context, coords []datasource.Coord) (map[string][]expand.Declaration, error) {
	out := map[string][]expand.Declaration{}
	for _, c := range coords {
		if d, ok := f.table[c.Key()]; ok {
			out[c.Key()] = d
		}
	}
	return out, nil
}

func (f *fakePyPI) Versions(_ context.Context, _, name string) ([]string, error) {
	return f.versions[name], nil
}

func (*fakePyPI) CompareVersions(a, b string) int {
	return semver.Parse(pad(a)).Compare(semver.Parse(pad(b)))
}

// pad turns "2.0" into "2.0.0" — a PEP 440 constraint is routinely partial, and
// semver.Parse rejects it, which would silently exclude every candidate.
func pad(v string) string {
	for strings.Count(v, ".") < 2 {
		v += ".0"
	}
	return v
}

func (f *fakePyPI) Satisfies(constraint, version string) (bool, bool) {
	switch {
	case constraint == "":
		return true, true
	case strings.HasPrefix(constraint, ">="):
		want := semver.Parse(pad(strings.TrimSpace(constraint[2:])))
		return semver.Parse(pad(version)).Compare(want) >= 0, true
	case strings.HasPrefix(constraint, "<"):
		want := semver.Parse(pad(strings.TrimSpace(constraint[1:])))
		return semver.Parse(pad(version)).Compare(want) < 0, true
	case strings.HasPrefix(constraint, "=="):
		return version == strings.TrimSpace(constraint[2:]), true
	}
	return false, false // an unreadable grammar, not an exclusion
}

func rootWith(t *testing.T, pins map[string]string) (*graph.Graph, *graph.Node) {
	t.Helper()
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/app", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "app"})
	g.MarkRoot(root.ID)
	for name, ver := range pins {
		n := g.AddNode(&graph.Node{
			ID: "pkg:pypi/" + name + "@" + ver, Kind: graph.KindPackage,
			Ecosystem: "pypi", Name: name, Version: ver, Direct: true, Depth: 1,
		})
		g.AddEdge(root.ID, n.ID, graph.EdgeDependsOn)
	}
	return g, root
}

func dump(t *testing.T, g *graph.Graph) {
	t.Helper()
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-32s truth=%-9s cand=%-3s frontier=%-4s constraint=%q",
			n.Depth, n.ID, n.Attr[graph.AttrVersionTruth],
			n.Attr[graph.AttrVersionCandidates], n.Attr[expand.AttrFrontier],
			n.Attr[graph.AttrDeclaredConstraint])
	}
}

// The motivating case, carried to depth N. One pin in requirements.txt; the
// walk reads three layers below it, and every version it chose says so.
func TestWalksBeyondFaceValue(t *testing.T) {
	d := &fakePyPI{
		table: map[string][]expand.Declaration{
			"pypi|totallyinnocent|0.11.2": {
				{Name: "requests", Constraint: ">=2.0"},
				{Name: "Flask_SQLAlchemy", Constraint: ">=3.0"},
				{Name: "pytest", Constraint: ">=7", Optional: true},
			},
			"pypi|requests|2.31.0":        {{Name: "urllib3", Constraint: ">=1.21"}},
			"pypi|flask-sqlalchemy|3.1.1": {{Name: "urllib3", Constraint: "<2.0"}},
			"pypi|urllib3|1.26.18":        {{Name: "quietleaf", Constraint: ""}},
			"pypi|quietleaf|9.0.0":        {},
		},
		versions: map[string][]string{
			"requests":         {"2.0.0", "2.28.1", "2.31.0"},
			"flask-sqlalchemy": {"3.0.5", "3.1.1"},
			"urllib3":          {"1.26.18", "2.0.7", "2.2.1"},
			"quietleaf":        {"9.0.0"},
		},
	}
	g, root := rootWith(t, map[string]string{"totallyinnocent": "0.11.2"})

	res, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dump(t, g)
	t.Logf("%+v", res)

	if res.DepthReached < 4 {
		t.Errorf("depth reached = %d, want >= 4", res.DepthReached)
	}
	// urllib3 has two parents with conflicting-direction constraints; both are
	// accumulated before presuming, so 1.26.18 is the only version satisfying
	// >=1.21 AND <2.0. Presuming per-parent would have picked 2.2.1 and lost it.
	u := g.Get("pkg:pypi/urllib3@1.26.18")
	if u == nil {
		t.Fatal("urllib3 not presumed from the accumulated constraints")
	}
	if got := u.Attr[graph.AttrDeclaredConstraint]; got != "<2.0, >=1.21" {
		t.Errorf("constraints = %q, want both parents' accumulated", got)
	}
	if u.Attr[graph.AttrVersionCandidates] != "1" {
		t.Errorf("candidates = %q, want 1 — the door was one version wide", u.Attr[graph.AttrVersionCandidates])
	}
	if !u.Presumed() {
		t.Error("a version this tool chose must not read as observed")
	}
	// The pinned node stays a fact.
	if got := g.Get("pkg:pypi/totallyinnocent@0.11.2").Attr[graph.AttrVersionTruth]; got != graph.TruthObserved {
		t.Errorf("pinned truth = %q, want observed", got)
	}
	// The leaf that genuinely declares nothing is a leaf, not a frontier.
	if g.Get("pkg:pypi/quietleaf@9.0.0").Attr[expand.AttrFrontier] == "true" {
		t.Error("a package that declares nothing is a leaf")
	}
}

// Constraints admitting nothing: the walk does not pick a side (the D-40 rule
// at the version level).
func TestUnsatisfiableConstraintsAreContestedNotGuessed(t *testing.T) {
	d := &fakePyPI{
		table: map[string][]expand.Declaration{
			"pypi|a|1.0.0": {{Name: "shared", Constraint: ">=3.0"}},
			"pypi|b|1.0.0": {{Name: "shared", Constraint: "<2.0"}},
		},
		versions: map[string][]string{"shared": {"1.0.0", "3.0.0"}},
	}
	g, root := rootWith(t, map[string]string{"a": "1.0.0", "b": "1.0.0"})
	res, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dump(t, g)
	n := g.Get("pkg:pypi/shared")
	if n == nil || n.Version != "" {
		t.Fatalf("want an unversioned contested node, got %+v", n)
	}
	if n.Attr[graph.AttrVersionTruth] != graph.TruthContested || res.Contested != 1 {
		t.Errorf("truth=%q contested=%d", n.Attr[graph.AttrVersionTruth], res.Contested)
	}
	if n.Attr[expand.AttrFrontier] != "true" {
		t.Error("a contested node stops the walk and must say so")
	}
}

// An unreadable constraint grammar is neither satisfied nor violated.
func TestUnevaluableConstraintDoesNotSilentlyExclude(t *testing.T) {
	d := &fakePyPI{
		table:    map[string][]expand.Declaration{"pypi|a|1.0.0": {{Name: "weird", Constraint: "~=!?1.0"}}},
		versions: map[string][]string{"weird": {"1.0.0", "2.0.0"}},
	}
	g, root := rootWith(t, map[string]string{"a": "1.0.0"})
	if _, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, expand.Options{}); err != nil {
		t.Fatal(err)
	}
	n := g.Get("pkg:pypi/weird")
	if n == nil || n.Attr[graph.AttrVersionTruth] != graph.TruthContested {
		t.Fatalf("want contested, got %+v", n)
	}
}

// NoPresume is the strictest posture: nothing in the graph that a file did not
// state. The walk still discovers names, and still stops at one layer.
func TestNoPresumeStaysNameOnly(t *testing.T) {
	d := &fakePyPI{
		table:    map[string][]expand.Declaration{"pypi|a|1.0.0": {{Name: "requests", Constraint: ">=2.0"}}},
		versions: map[string][]string{"requests": {"2.31.0"}},
	}
	g, root := rootWith(t, map[string]string{"a": "1.0.0"})
	res, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, expand.Options{NoPresume: true})
	if err != nil {
		t.Fatal(err)
	}
	n := g.Get("pkg:pypi/requests")
	if n == nil || n.Version != "" || res.Presumed != 0 {
		t.Fatalf("want a name-only node, got %+v presumed=%d", n, res.Presumed)
	}
	if n.Attr[expand.AttrFrontier] != "true" {
		t.Error("name-only nodes are the frontier")
	}
}

// Per-root, name-only: a declaration must never be MATCHED against another
// root's pinned package. In name-only mode A's requests stays unversioned and
// distinct from B's pinned coordinate.
func TestDeclarationNeverBorrowsAnotherRootsPin(t *testing.T) {
	d := &fakePyPI{
		table:    map[string][]expand.Declaration{"pypi|totallyinnocent|0.11.2": {{Name: "requests", Constraint: ">=2.0"}}},
		versions: map[string][]string{"requests": {"2.31.0"}},
	}
	g, rootA := rootWith(t, map[string]string{"totallyinnocent": "0.11.2"})
	rootB := g.AddNode(&graph.Node{ID: "pkg:pypi/other", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "other"})
	g.MarkRoot(rootB.ID)
	pinned := g.AddNode(&graph.Node{
		ID: "pkg:pypi/requests@2.31.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "requests", Version: "2.31.0", Depth: 1,
	})
	pinned.Attr = map[string]string{graph.AttrVersionTruth: graph.TruthObserved}
	g.AddEdge(rootB.ID, pinned.ID, graph.EdgeDependsOn)

	// NoPresume: the match-not-borrow rule is a name-only property. With
	// presuming on, A independently presumes a version from the registry and a
	// legitimate identity match is dedup, not borrowing (covered below).
	if _, err := expand.NewWalker(d).ExpandRoot(context.Background(), g, rootA, expand.Options{NoPresume: true}); err != nil {
		t.Fatal(err)
	}
	for _, e := range g.SortedEdges() {
		if e.To == pinned.ID && strings.Contains(e.From, "totallyinnocent") {
			t.Fatal("root A's declaration was satisfied by root B's observed pin")
		}
	}
	if g.Get("pkg:pypi/requests") == nil {
		t.Error("want a separate unversioned node under root A")
	}
}

// Per-root, presuming: A presumes a version INDEPENDENTLY from the registry, so
// when B has pinned a version A's constraint excludes, A must not attach to it.
// This is the containment guarantee that survives presuming: A's resolution
// cannot be swayed by what another root happened to pin.
func TestPresumedResolutionIgnoresAnotherRootsPin(t *testing.T) {
	d := &fakePyPI{
		table: map[string][]expand.Declaration{"pypi|totallyinnocent|0.11.2": {{Name: "requests", Constraint: ">=2.0"}}},
		// The registry publishes 2.31.0; B pinned an out-of-range 1.0.0.
		versions: map[string][]string{"requests": {"1.0.0", "2.31.0"}},
	}
	g, rootA := rootWith(t, map[string]string{"totallyinnocent": "0.11.2"})
	rootB := g.AddNode(&graph.Node{ID: "pkg:pypi/other", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "other"})
	g.MarkRoot(rootB.ID)
	stale := g.AddNode(&graph.Node{
		ID: "pkg:pypi/requests@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "requests", Version: "1.0.0", Depth: 1,
		Attr: map[string]string{graph.AttrVersionTruth: graph.TruthObserved},
	})
	g.AddEdge(rootB.ID, stale.ID, graph.EdgeDependsOn)

	if _, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, rootA, expand.Options{}); err != nil {
		t.Fatal(err)
	}
	// A presumes 2.31.0 (its constraint excludes B's 1.0.0), a distinct node.
	if g.Get("pkg:pypi/requests@2.31.0") == nil {
		t.Error("A did not presume its own in-range version")
	}
	for _, e := range g.SortedEdges() {
		if e.To == stale.ID && strings.Contains(e.From, "totallyinnocent") {
			t.Fatal("A attached to B's out-of-range pin instead of presuming its own")
		}
	}
}

// A coordinate absent from the response was NOT READ — not a confident leaf.
func TestUnreadCoordinateIsNotAConfidentLeaf(t *testing.T) {
	d := &fakePyPI{table: map[string][]expand.Declaration{"pypi|quiet|1.0.0": {}}}
	g, root := rootWith(t, map[string]string{"totallyinnocent": "0.11.2", "quiet": "1.0.0"})
	res, err := expand.NewWalker(d).ExpandRoot(context.Background(), g, root, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Unread != 1 {
		t.Errorf("unread = %d, want 1", res.Unread)
	}
	if g.Get("pkg:pypi/totallyinnocent@0.11.2").Attr[expand.AttrFrontier] != "true" {
		t.Error("unread package must be a frontier")
	}
	if g.Get("pkg:pypi/quiet@1.0.0").Attr[expand.AttrFrontier] == "true" {
		t.Error("a package that genuinely declares nothing is a leaf")
	}
}

// A non-registry origin (git/path/url) is never queried against a package
// registry: its name could collide with a real registry package, and grafting
// that package's dependencies onto a local fork is the name-confusion the
// source class exists to prevent.
func TestNonRegistrySourceIsNotWalked(t *testing.T) {
	d := &fakePyPI{
		// If this were queried, "forked-lib" would declare a dependency.
		table:    map[string][]expand.Declaration{"pypi|forked-lib|1.0.0": {{Name: "should-not-appear", Constraint: ">=1.0"}}},
		versions: map[string][]string{"should-not-appear": {"1.0.0"}},
	}
	g := graph.New()
	root := g.AddNode(&graph.Node{ID: "pkg:pypi/app", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "app"})
	g.MarkRoot(root.ID)
	// A git-sourced fork, not a registry package.
	fork := &graph.Node{ID: "pkg:pypi/forked-lib@1.0.0", Kind: graph.KindPackage,
		Ecosystem: "pypi", Name: "forked-lib", Version: "1.0.0", Depth: 1}
	fork.SetSource(graph.SourceGit, "git+https://github.com/someone/forked-lib")
	g.AddNode(fork)
	g.AddEdge(root.ID, fork.ID, graph.EdgeDependsOn)

	res, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if g.Get("pkg:pypi/should-not-appear") != nil {
		t.Error("walked a git-sourced fork against the registry — name-confusion vector")
	}
	if res.Discovered != 0 {
		t.Errorf("discovered = %d from a non-registry node, want 0", res.Discovered)
	}
}

// lowestFake is a Presumer that also implements LowestResolver, to prove the
// selection direction is per-ecosystem: the same candidate set resolves to the
// lowest here and the highest for a plain Presumer.
type lowestFake struct{ *fakePyPI }

func (lowestFake) Ecosystem() string   { return "nuget" }
func (lowestFake) PrefersLowest() bool { return true }
func (f lowestFake) Identify(name, version string) (string, string) {
	id := "pkg:nuget/" + name
	if version != "" {
		id += "@" + version
	}
	return id, name
}

func TestSelectionDirectionIsPerEcosystem(t *testing.T) {
	// Same shape, two ecosystems: highest-wins (fakePyPI) vs lowest-wins.
	mk := func() (*graph.Graph, *graph.Node) {
		g := graph.New()
		root := g.AddNode(&graph.Node{ID: "root", Kind: graph.KindPackage})
		g.MarkRoot(root.ID)
		return g, root
	}

	hi := &fakePyPI{
		table:    map[string][]expand.Declaration{"pypi|a|1.0.0": {{Name: "dep", Constraint: ">=1.0"}}},
		versions: map[string][]string{"dep": {"1.0.0", "1.5.0", "2.0.0"}},
	}
	g, root := mk()
	root.Ecosystem = "pypi"
	pin := g.AddNode(&graph.Node{ID: "pkg:pypi/a@1.0.0", Kind: graph.KindPackage, Ecosystem: "pypi", Name: "a", Version: "1.0.0", Depth: 1})
	g.AddEdge(root.ID, pin.ID, graph.EdgeDependsOn)
	if _, err := expand.NewWalker(hi).ExpandRoot(context.Background(), g, pin, expand.Options{}); err != nil {
		t.Fatal(err)
	}
	if g.Get("pkg:pypi/dep@2.0.0") == nil {
		t.Error("highest-wins ecosystem did not take the newest satisfying version")
	}

	lo := lowestFake{&fakePyPI{
		table:    map[string][]expand.Declaration{"nuget|a|1.0.0": {{Name: "dep", Constraint: ">=1.0"}}},
		versions: map[string][]string{"dep": {"1.0.0", "1.5.0", "2.0.0"}},
	}}
	g2, root2 := mk()
	root2.Ecosystem = "nuget"
	pin2 := g2.AddNode(&graph.Node{ID: "pkg:nuget/a@1.0.0", Kind: graph.KindPackage, Ecosystem: "nuget", Name: "a", Version: "1.0.0", Depth: 1})
	g2.AddEdge(root2.ID, pin2.ID, graph.EdgeDependsOn)
	if _, err := expand.NewWalker(lo).ExpandRoot(context.Background(), g2, pin2, expand.Options{}); err != nil {
		t.Fatal(err)
	}
	if g2.Get("pkg:nuget/dep@1.0.0") == nil {
		t.Error("lowest-wins ecosystem did not take the oldest satisfying version")
	}
	if g2.Get("pkg:nuget/dep@2.0.0") != nil {
		t.Error("lowest-wins ecosystem wrongly took the newest")
	}
}

// The manifest-only case the trial exposed: a root that declares direct deps
// with constraints but no lockfile pinned them (unpinned requirements.txt,
// pyproject [project]). The adapter records them on the root; expansion must
// presume versions and walk from them. Before the seed phase this discovered
// nothing.
func TestSeedsFromManifestDeclaredDeps(t *testing.T) {
	d := &fakePyPI{
		table: map[string][]expand.Declaration{
			"pypi|fastapi|0.110.0": {{Name: "starlette", Constraint: ">=0.36"}},
		},
		versions: map[string][]string{
			"fastapi":   {"0.100.0", "0.110.0"},
			"starlette": {"0.36.0", "0.37.0"},
		},
	}
	g := graph.New()
	// A manifest-only root: versioned (the project itself) but its deps are only
	// declared, not pinned — recorded in AttrDeclaredDeps, no child nodes.
	root := g.AddNode(&graph.Node{
		ID: "pkg:pypi/app@0.0.0", Kind: graph.KindPackage, Ecosystem: "pypi",
		Name: "app", Version: "0.0.0",
		Attr: map[string]string{
			graph.AttrDeclaredDeps: graph.EncodeDeclaredDeps([]graph.DeclaredDep{
				{Name: "fastapi", Constraint: ">=0.100"},
			}),
		},
	})
	g.MarkRoot(root.ID)

	res, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, expand.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-28s truth=%s", n.Depth, n.ID, n.VersionTruth())
	}
	// fastapi presumed to highest satisfying >=0.100, then its own dep walked.
	fa := g.Get("pkg:pypi/fastapi@0.110.0")
	if fa == nil {
		t.Fatal("declared dep fastapi was not seeded and presumed")
	}
	if !fa.Presumed() || fa.Depth != 1 || !fa.Direct {
		t.Errorf("fastapi node wrong: presumed=%v depth=%d direct=%v", fa.Presumed(), fa.Depth, fa.Direct)
	}
	if g.Get("pkg:pypi/starlette@0.37.0") == nil {
		t.Error("transitive dep of a seeded declared dep was not walked (depth 2 not reached)")
	}
	if res.Discovered < 2 {
		t.Errorf("discovered = %d, want >= 2 (fastapi + starlette)", res.Discovered)
	}
}

// stubResolver is a Resolver over a fixed table of resolved graphs, keyed
// "ecosystem|name|version". It stands in for deps.dev so a test can exercise the
// asserted tier without a network.
type stubResolver struct {
	graphs map[string]expand.ResolvedGraph
	calls  []string // every coordinate the walk actually asked about
}

func (*stubResolver) Name() string { return "deps.dev-stub" }

func (s *stubResolver) Resolve(_ context.Context, eco, name, version string) (expand.ResolvedGraph, bool, error) {
	s.calls = append(s.calls, eco+"|"+name+"|"+version)
	rg, ok := s.graphs[eco+"|"+name+"|"+version]
	return rg, ok, nil
}

// TestAssertedTierFiresOnRegistryDirectDeps pins OPU-06: with a Resolver set, a
// manifest-only LOCAL project (path origin — not itself registry-queryable) must
// still reach the asserted tier, because the resolver is handed the project's
// registry-queryable DIRECT dependency, not the un-queryable root. Before the
// fix the resolver was aimed at the root, returned immediately, and every
// transitive node fell through to `presumed` — the tier never fired.
func TestAssertedTierFiresOnRegistryDirectDeps(t *testing.T) {
	d := &fakePyPI{
		table: map[string][]expand.Declaration{
			// requests declares urllib3; the presume path WOULD walk this, but the
			// resolver closes the subtree first, so these must come back asserted.
			"pypi|requests|2.31.0": {{Name: "urllib3", Constraint: ">=1.21"}},
		},
		versions: map[string][]string{
			"requests": {"2.31.0"},
			"urllib3":  {"2.0.0", "2.2.0"},
			"certifi":  {"2024.2.2"},
		},
	}
	// deps.dev's answer for requests@2.31.0: a concrete subtree (urllib3, certifi).
	resolver := &stubResolver{graphs: map[string]expand.ResolvedGraph{
		"pypi|requests|2.31.0": {
			Nodes: []expand.ResolvedRef{
				{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}, // index 0: the queried dep
				{Ecosystem: "pypi", Name: "urllib3", Version: "2.2.0"},
				{Ecosystem: "pypi", Name: "certifi", Version: "2024.2.2"},
			},
			Edges: []expand.ResolvedEdge{{From: 0, To: 1}, {From: 0, To: 2}},
		},
	}}

	g := graph.New()
	// The operator's own local project: a PATH-origin root, exactly what a real
	// scan hands the walk. It is not registry-queryable, so aiming a resolver at
	// it (the OPU-06 bug) can never resolve anything.
	root := g.AddNode(&graph.Node{
		ID: "pkg:pypi/myapp@0.0.0", Kind: graph.KindPackage, Ecosystem: "pypi",
		Name: "myapp", Version: "0.0.0",
		Attr: map[string]string{
			graph.AttrDeclaredDeps: graph.EncodeDeclaredDeps([]graph.DeclaredDep{
				{Name: "requests", Constraint: "==2.31.0"},
			}),
		},
	})
	root.SetSource(graph.SourcePath, "")
	g.MarkRoot(root.ID)

	res, err := expand.NewWalker(d).WithVersionIndex(d).
		ExpandRoot(context.Background(), g, root, expand.Options{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.SortedNodes() {
		t.Logf("d%d %-30s truth=%s by=%s", n.Depth, n.ID, n.VersionTruth(), n.Attr[expand.AttrAssertedBy])
	}

	// The resolver must have been asked about the DIRECT DEP, never the root.
	for _, c := range resolver.calls {
		if strings.Contains(c, "myapp") {
			t.Errorf("resolver was handed the un-queryable project root: %q", c)
		}
	}

	if res.Asserted < 2 {
		t.Fatalf("asserted = %d, want >= 2 (urllib3 + certifi); the tier did not fire", res.Asserted)
	}

	// The resolved children carry the asserted truth tier and attribution.
	for _, id := range []string{"pkg:pypi/urllib3@2.2.0", "pkg:pypi/certifi@2024.2.2"} {
		n := g.Get(id)
		if n == nil {
			t.Fatalf("asserted child %s missing", id)
		}
		if n.VersionTruth() != graph.TruthAsserted {
			t.Errorf("%s truth = %q, want asserted", id, n.VersionTruth())
		}
		if n.Attr[expand.AttrAssertedBy] != "deps.dev-stub" {
			t.Errorf("%s asserted_by = %q, want deps.dev-stub", id, n.Attr[expand.AttrAssertedBy])
		}
		// root(0) -> requests(1) -> child: the asserted child ladders to depth 2,
		// not depth 0. A depth-0 transitive node reads as a root (the OPU-04 class
		// of bug, one tier down), so pin it.
		if n.Depth != 2 {
			t.Errorf("%s depth = %d, want 2", id, n.Depth)
		}
	}

	// The presume walk must NOT have re-derived urllib3 from the constraint: the
	// resolver said 2.2.0, and a presumed second copy at a different version would
	// mean the subtree was not closed. urllib3 exists once, asserted.
	if presumed := g.Get("pkg:pypi/urllib3@2.0.0"); presumed != nil {
		t.Error("urllib3 was re-presumed beneath an asserted subtree; the subtree was not closed")
	}
}

// stubLocalResolver implements both Resolver (the per-dependency union path) and
// LocalRootResolver (the whole-root path). It records which path the walker took.
type stubLocalResolver struct {
	whole      expand.ResolvedGraph            // the whole-root answer
	perDep     map[string]expand.ResolvedGraph // per-direct-dependency answers
	localCalls int
	depCalls   []string
}

func (*stubLocalResolver) Name() string { return "go-proxy-stub" }

func (s *stubLocalResolver) Resolve(_ context.Context, _, name, version string) (expand.ResolvedGraph, bool, error) {
	s.depCalls = append(s.depCalls, name+"@"+version)
	rg, ok := s.perDep[name+"@"+version]
	return rg, ok, nil
}

func (s *stubLocalResolver) ResolveLocalRoot(_ context.Context, _ expand.LocalRoot) (expand.ResolvedGraph, bool, error) {
	s.localCalls++
	return s.whole, true, nil
}

// TestWholeRootResolutionReplacesUnion pins OPU-15-exact at the walker: when the
// resolver supports LocalRootResolver, ExpandRoot resolves the LOCAL main
// module's whole build list in one shot and does NOT resolve each direct
// dependency independently. The tell is a shared module two direct deps require
// at different versions: the whole-root answer collapses it to one version; the
// per-dependency union (the path that must NOT run) would leave both.
func TestWholeRootResolutionReplacesUnion(t *testing.T) {
	id := func(name, ver string) string { return "pkg:gomod/" + name + "@" + ver }
	ref := func(name, ver string) expand.ResolvedRef {
		return expand.ResolvedRef{Ecosystem: "gomod", Name: name, Version: ver}
	}
	resolver := &stubLocalResolver{
		// Whole-root build list: M, A, B, X v2.0.0 — X once (MVS max).
		whole: expand.ResolvedGraph{
			Nodes: []expand.ResolvedRef{ref("M", "0.0.0"), ref("A", "v1.0.0"), ref("B", "v1.0.0"), ref("X", "v2.0.0")},
			Edges: []expand.ResolvedEdge{{From: 0, To: 1}, {From: 0, To: 2}, {From: 1, To: 3}, {From: 2, To: 3}},
		},
		// The per-dependency path, if wrongly taken, would add X at BOTH versions.
		perDep: map[string]expand.ResolvedGraph{
			"A@v1.0.0": {Nodes: []expand.ResolvedRef{ref("A", "v1.0.0"), ref("X", "v2.0.0")}, Edges: []expand.ResolvedEdge{{From: 0, To: 1}}},
			"B@v1.0.0": {Nodes: []expand.ResolvedRef{ref("B", "v1.0.0"), ref("X", "v1.0.0")}, Edges: []expand.ResolvedEdge{{From: 0, To: 1}}},
		},
	}

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: id("M", "0.0.0"), Kind: graph.KindPackage, Ecosystem: "gomod", Name: "M", Version: "0.0.0"})
	root.SetSource(graph.SourcePath, "")
	g.MarkRoot(root.ID)
	for _, d := range [][2]string{{"A", "v1.0.0"}, {"B", "v1.0.0"}} {
		dep := g.AddNode(&graph.Node{ID: id(d[0], d[1]), Kind: graph.KindPackage, Ecosystem: "gomod", Name: d[0], Version: d[1], Depth: 1})
		g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)
	}

	if _, err := expand.NewWalker().ExpandRoot(context.Background(), g, root, expand.Options{Resolver: resolver}); err != nil {
		t.Fatal(err)
	}

	if resolver.localCalls != 1 {
		t.Errorf("ResolveLocalRoot called %d times, want 1", resolver.localCalls)
	}
	if len(resolver.depCalls) != 0 {
		t.Errorf("per-dependency Resolve was called %v; the whole-root path must replace the union", resolver.depCalls)
	}
	if g.Get(id("X", "v2.0.0")) == nil {
		t.Error("X v2.0.0 (the MVS-collapsed build-list version) missing from the graph")
	}
	if g.Get(id("X", "v1.0.0")) != nil {
		t.Error("X v1.0.0 present: the per-dependency union ran and left a second version of the shared module")
	}
	if n := g.Get(id("X", "v2.0.0")); n != nil && n.VersionTruth() != graph.TruthAsserted {
		t.Errorf("X truth = %q, want asserted", n.VersionTruth())
	}
}

// stubIncompleteResolver is a LocalRootResolver that returns a real partial build
// list AND an *IncompleteResolution flagging one node's subtree as unread — the
// shape a gomod resolver produces on a transient go.mod fetch failure (OPU-17).
type stubIncompleteResolver struct {
	whole  expand.ResolvedGraph
	unread []expand.ResolvedRef
}

func (*stubIncompleteResolver) Name() string { return "go-proxy-stub" }

func (*stubIncompleteResolver) Resolve(_ context.Context, _, _, _ string) (expand.ResolvedGraph, bool, error) {
	return expand.ResolvedGraph{}, false, nil
}

func (s *stubIncompleteResolver) ResolveLocalRoot(_ context.Context, _ expand.LocalRoot) (expand.ResolvedGraph, bool, error) {
	return s.whole, true, &expand.IncompleteResolution{Unread: s.unread}
}

// TestIncompleteResolutionMarksUnreadAndDegradesCoverage pins OPU-17 at the
// walker: when a resolver returns a partial build list with an *IncompleteResolution,
// ExpandRoot KEEPS the partial graph (no discard, no union fallback), marks the
// unread node a frontier with the subtree-unread reason, and counts it as unread
// so coverage degrades visibly. A transient network hole must never pass as a
// clean, complete resolution.
func TestIncompleteResolutionMarksUnreadAndDegradesCoverage(t *testing.T) {
	id := func(name, ver string) string { return "pkg:gomod/" + name + "@" + ver }
	ref := func(name, ver string) expand.ResolvedRef {
		return expand.ResolvedRef{Ecosystem: "gomod", Name: name, Version: ver}
	}
	resolver := &stubIncompleteResolver{
		whole: expand.ResolvedGraph{
			Nodes: []expand.ResolvedRef{ref("M", "0.0.0"), ref("A", "v1.0.0"), ref("B", "v1.0.0")},
			Edges: []expand.ResolvedEdge{{From: 0, To: 1}, {From: 0, To: 2}},
		},
		unread: []expand.ResolvedRef{ref("A", "v1.0.0")}, // A's subtree could not be read
	}

	g := graph.New()
	root := g.AddNode(&graph.Node{ID: id("M", "0.0.0"), Kind: graph.KindPackage, Ecosystem: "gomod", Name: "M", Version: "0.0.0"})
	root.SetSource(graph.SourcePath, "")
	g.MarkRoot(root.ID)
	for _, d := range [][2]string{{"A", "v1.0.0"}, {"B", "v1.0.0"}} {
		dep := g.AddNode(&graph.Node{ID: id(d[0], d[1]), Kind: graph.KindPackage, Ecosystem: "gomod", Name: d[0], Version: d[1], Depth: 1})
		g.AddEdge(root.ID, dep.ID, graph.EdgeDependsOn)
	}

	res, err := expand.NewWalker().ExpandRoot(context.Background(), g, root, expand.Options{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}

	// The partial build list is kept.
	if g.Get(id("A", "v1.0.0")) == nil || g.Get(id("B", "v1.0.0")) == nil {
		t.Fatal("partial build list was discarded; a transient hole must not throw away resolved work")
	}
	// The unread node is marked, both as a frontier and with the explicit reason.
	a := g.Get(id("A", "v1.0.0"))
	if a.Attr[expand.AttrSubtreeUnread] != "transient-fetch-failure" {
		t.Errorf("A subtree-unread attr = %q, want %q", a.Attr[expand.AttrSubtreeUnread], "transient-fetch-failure")
	}
	if a.Attr[expand.AttrFrontier] != "true" {
		t.Error("A is not a frontier: an unread subtree must read as a stopped walk, not a confident leaf")
	}
	// B, fully resolved, is NOT marked.
	if b := g.Get(id("B", "v1.0.0")); b.Attr[expand.AttrSubtreeUnread] != "" {
		t.Error("B wrongly marked unread: only the transiently-failed node should be")
	}
	// Coverage degrades: the unread node is counted.
	if res.Unread < 1 {
		t.Errorf("res.Unread = %d, want >= 1 (a transient hole must degrade coverage visibly)", res.Unread)
	}
}
