package nuget

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/graph"
)

func TestDetect(t *testing.T) {
	a := New()
	if !a.Detect("testdata") {
		t.Error("should detect testdata directory with packages.lock.json")
	}
	if !a.Detect("testdata/packages.lock.json") {
		t.Error("should detect testdata/packages.lock.json directly")
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

	// Expect: root + Newtonsoft.Json + Serilog + Serilog.Sinks.Console = 4 nodes
	nodes := g.SortedNodes()
	if len(nodes) != 4 {
		for _, n := range nodes {
			t.Logf("  node: %s (name=%s, depth=%d, direct=%v)", n.ID, n.Name, n.Depth, n.Direct)
		}
		t.Fatalf("nodes = %d, want 4", len(nodes))
	}

	// NuGet names are lowercased for deduplication.
	nj := g.Get("pkg:nuget/newtonsoft.json@13.0.1")
	if nj == nil {
		t.Fatal("Newtonsoft.Json node missing (should be lowercased)")
	}
	if !nj.Direct {
		t.Error("Newtonsoft.Json should be direct")
	}

	serilog := g.Get("pkg:nuget/serilog@3.0.1")
	if serilog == nil {
		t.Fatal("Serilog node missing")
	}
	if !serilog.Direct {
		t.Error("Serilog should be direct")
	}

	ssc := g.Get("pkg:nuget/serilog.sinks.console@4.1.0")
	if ssc == nil {
		t.Fatal("Serilog.Sinks.Console node missing")
	}
}

func TestResolveEdges(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Serilog -> Serilog.Sinks.Console edge.
	serilogID := "pkg:nuget/serilog@3.0.1"
	sscID := "pkg:nuget/serilog.sinks.console@4.1.0"
	var found bool
	for _, e := range g.SortedEdges() {
		if e.From == serilogID && e.To == sscID {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing edge: serilog -> serilog.sinks.console")
	}
}

// AV-05: different versions of the same package across TFMs must both appear
// in the graph. The old name-only dedup key dropped the net8.0 version.
func TestResolveMultiTFMRetainsBothVersions(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/multi-tfm")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	v6 := g.Get("pkg:nuget/microsoft.extensions.logging@6.0.0")
	v8 := g.Get("pkg:nuget/microsoft.extensions.logging@8.0.0")
	if v6 == nil {
		t.Error("net6.0 version (6.0.0) missing from graph")
	}
	if v8 == nil {
		t.Error("net8.0 version (8.0.0) missing from graph")
	}

	// Both versions should be in the graph: root + v6 + v8 = 3 nodes.
	nodes := g.SortedNodes()
	if len(nodes) != 3 {
		for _, n := range nodes {
			t.Logf("  node: %s (name=%s, version=%s)", n.ID, n.Name, n.Version)
		}
		t.Fatalf("nodes = %d, want 3 (root + 2 versions)", len(nodes))
	}
}

// AV-05: cross-TFM edges must link to the version resolved within the SAME
// TFM. When dependency values are version ranges, the fallback must use the
// per-TFM index, not a nondeterministic map scan.
func TestResolveMultiTFMEdgeIdentity(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/multi-tfm-edges")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	a6 := "pkg:nuget/packagea@6.0.0"
	a8 := "pkg:nuget/packagea@8.0.0"
	b1 := "pkg:nuget/packageb@1.0.0"
	b2 := "pkg:nuget/packageb@2.0.0"

	// Verify all nodes exist.
	for _, id := range []string{a6, a8, b1, b2} {
		if g.Get(id) == nil {
			t.Fatalf("node %s missing from graph", id)
		}
	}

	// Verify correct edges exist and incorrect cross-TFM edges do not.
	type edgePair struct{ from, to string }
	wantEdges := map[edgePair]bool{
		{a6, b1}: true,
		{a8, b2}: true,
	}
	badEdges := map[edgePair]bool{
		{a6, b2}: true,
		{a8, b1}: true,
	}

	for _, e := range g.SortedEdges() {
		ep := edgePair{e.From, e.To}
		if wantEdges[ep] {
			delete(wantEdges, ep)
		}
		if badEdges[ep] {
			t.Errorf("cross-TFM edge should not exist: %s -> %s", e.From, e.To)
		}
	}
	for ep := range wantEdges {
		t.Errorf("expected edge missing: %s -> %s", ep.from, ep.to)
	}
}

// AV-03: nested TFM-specific MSBuild payloads (e.g. build/net8.0/evil.targets)
// must produce install-hook nodes.
func TestNestedMSBuildTargetsProduceHook(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/msbuild-nested")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	err = a.ExtractInstallSurface("testdata/msbuild-nested", g)
	if err != nil {
		gaps := instsurf.GapsOf(err)
		if len(gaps) == 0 {
			t.Fatalf("ExtractInstallSurface: %v", err)
		}
	}

	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook {
			hookFound = true
			if n.Attr["cap.exec"] != "true" {
				t.Errorf("hook %q missing cap.exec", n.Name)
			}
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s", n.ID, n.Kind, n.Name)
		}
		t.Error("nested build/net8.0/evil.targets should produce an install-hook node")
	}
}

// AV-03: a dependency package's MSBuild payload must produce an install-hook
// node attributed to the DEPENDENCY PURL, not the project root.
func TestDependencyMSBuildHookAttribution(t *testing.T) {
	abs, err := filepath.Abs("testdata/nuget-dep-hook/nuget-cache")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NUGET_PACKAGES", abs)

	a := New()
	g, err := a.Resolve("testdata/nuget-dep-hook")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := a.ExtractInstallSurface("testdata/nuget-dep-hook", g); err != nil {
		t.Fatalf("ExtractInstallSurface: %v", err)
	}

	evilPkgID := "pkg:nuget/evilpackage@1.0.0"
	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == evilPkgID {
			hookFound = true
			if n.Attr["cap.exec"] != "true" {
				t.Error("hook missing cap.exec")
			}
			if n.Attr["cap.network"] != "true" {
				t.Error("hook missing cap.network (Invoke-WebRequest in evil.targets)")
			}
			if n.Attr["cap.credentials"] != "true" {
				t.Error("hook missing cap.credentials (NUGET_API_KEY in evil.targets)")
			}
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s hook.package=%s", n.ID, n.Kind, n.Name, n.Attr["hook.package"])
		}
		t.Error("EvilPackage@1.0.0 should own the declares-hook edge, not the project root")
	}

	// The project root must NOT own the dependency's hook.
	rootID := g.Roots[0]
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook && n.Attr["hook.package"] == rootID {
			t.Error("project root should not own the dependency's hook")
		}
	}
}

// AV-03: buildMultiTargeting MSBuild payloads must produce install-hook nodes.
func TestBuildMultiTargetingProducesHook(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata/msbuild-multitargeting")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	err = a.ExtractInstallSurface("testdata/msbuild-multitargeting", g)
	if err != nil {
		gaps := instsurf.GapsOf(err)
		if len(gaps) == 0 {
			t.Fatalf("ExtractInstallSurface: %v", err)
		}
	}

	var hookFound bool
	for _, n := range g.SortedNodes() {
		if n.Kind == graph.KindInstallHook {
			hookFound = true
			if n.Attr["cap.exec"] != "true" {
				t.Errorf("hook %q missing cap.exec", n.Name)
			}
			break
		}
	}
	if !hookFound {
		for _, n := range g.SortedNodes() {
			t.Logf("  node: %s kind=%s name=%s", n.ID, n.Kind, n.Name)
		}
		t.Error("buildMultiTargeting/evil.targets should produce an install-hook node")
	}
}

func TestResolveDepths(t *testing.T) {
	a := New()
	g, err := a.Resolve("testdata")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	ssc := g.Get("pkg:nuget/serilog.sinks.console@4.1.0")
	if ssc == nil {
		t.Fatal("Serilog.Sinks.Console node missing")
	}
	if ssc.Depth != 2 {
		t.Errorf("Serilog.Sinks.Console depth = %d, want 2", ssc.Depth)
	}
}

// OPU-14: the node Name must be the CANONICAL-case NuGet id, because the OSV
// coordinate is built straight from n.Name and OSV's NuGet ecosystem is
// case-sensitive. Lowercasing it silently missed every advisory. Dedup/identity
// (the PURL id) still fold case.
func TestNuGetNameIsCanonicalForOSV(t *testing.T) {
	lock := []byte(`{"version":1,"dependencies":{"net6.0":{
		"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.3"},
		"System.Net.Http":{"type":"Direct","resolved":"4.3.0"}
	}}}`)
	g, err := parsePackagesLock("proj", lock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Identity/PURL stays lowercase; the OSV-facing Name stays canonical.
	nj := g.Get("pkg:nuget/newtonsoft.json@12.0.3")
	if nj == nil {
		t.Fatal("Newtonsoft.Json node missing")
	}
	if nj.Name != "Newtonsoft.Json" {
		t.Errorf("node Name = %q, want canonical Newtonsoft.Json (OSV coordinate is case-sensitive)", nj.Name)
	}
	if snh := g.Get("pkg:nuget/system.net.http@4.3.0"); snh == nil || snh.Name != "System.Net.Http" {
		t.Errorf("System.Net.Http Name wrong: %+v", snh)
	}
}

// OPU-15: a packages.config (legacy XML manifest) is now claimed and parsed,
// not merely disclosed as an unresolvable gap. A leading UTF-8 BOM (common on
// Windows-authored configs) must be tolerated, and every <package> becomes a
// direct node with a canonical-case name for the case-sensitive OSV coordinate.
func TestPackagesConfigParses(t *testing.T) {
	a := New()
	dir := "testdata/packages-config"
	if !a.Detect(dir) {
		t.Fatal("should Detect a directory containing packages.config")
	}
	if !a.Detect(filepath.Join(dir, "packages.config")) {
		t.Fatal("should Detect a packages.config file directly")
	}
	g, err := a.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(g.Roots) != 1 {
		t.Fatalf("roots = %d, want 1", len(g.Roots))
	}
	// root + Bogus + Bootstrap + Newtonsoft.Json + System.Net.Http = 5 nodes.
	nodes := g.SortedNodes()
	if len(nodes) != 5 {
		for _, n := range nodes {
			t.Logf("  node: %s (name=%s, depth=%d, direct=%v)", n.ID, n.Name, n.Depth, n.Direct)
		}
		t.Fatalf("nodes = %d, want 5 (root + 4 packages)", len(nodes))
	}
	// Names must be canonical-case (the OPU-14 lesson applies to this parser too):
	// the OSV coordinate is built from n.Name and OSV's NuGet ecosystem is
	// case-sensitive. Identity/PURL still folds case.
	nj := g.Get("pkg:nuget/newtonsoft.json@12.0.3")
	if nj == nil {
		t.Fatal("Newtonsoft.Json node missing (BOM not stripped?)")
	}
	if nj.Name != "Newtonsoft.Json" {
		t.Errorf("node Name = %q, want canonical Newtonsoft.Json", nj.Name)
	}
	if !nj.Direct || nj.Depth != 1 {
		t.Errorf("Newtonsoft.Json: direct=%v depth=%d, want direct depth 1", nj.Direct, nj.Depth)
	}
	if snh := g.Get("pkg:nuget/system.net.http@4.3.0"); snh == nil || snh.Name != "System.Net.Http" {
		t.Errorf("System.Net.Http node wrong: %+v", snh)
	}
}

// OPU-15: a packages.config takes a back seat to a resolved lock — when both are
// present the lock (a full resolved tree) wins, exactly as the dir path does.
func TestPackagesConfigLockPrecedence(t *testing.T) {
	dir := t.TempDir()
	// A packages.config alongside a packages.lock.json: the lock must win.
	cfg := "<packages><package id=\"OnlyInConfig\" version=\"1.0.0\" /></packages>"
	if err := os.WriteFile(filepath.Join(dir, "packages.config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := `{"version":1,"dependencies":{"net6.0":{"OnlyInLock":{"type":"Direct","resolved":"2.0.0"}}}}`
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := New().Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Get("pkg:nuget/onlyinlock@2.0.0") == nil {
		t.Error("lock package missing — lock should take precedence")
	}
	if g.Get("pkg:nuget/onlyinconfig@1.0.0") != nil {
		t.Error("config package present — the lock should have won, config not read")
	}
}

// OPU-15: malformed XML must degrade honestly — an error the scan flow surfaces
// as incomplete coverage (D-59), never a crash or a silent clean pass.
func TestPackagesConfigMalformedIsError(t *testing.T) {
	// Truncated mid-element.
	if _, err := parsePackagesConfig("proj", []byte(`<packages><package id="X" version="1.0.0"`)); err == nil {
		t.Error("truncated packages.config must return an error, not a clean parse")
	}
	// Well-formed XML but no <package> entries → no packages to scan is an error,
	// so the caller degrades coverage rather than reporting a clean pass.
	if _, err := parsePackagesConfig("proj", []byte(`<packages></packages>`)); err == nil {
		t.Error("empty packages.config must return an error (nothing resolved)")
	}
}

// OPU-17: a Paket paket.lock (previously skipped in total silence) is parsed
// into NuGet nodes. NUGET-group packages across all groups become canonical-case
// nuget nodes; GITHUB/GIT sections are skipped; a package listed both as a
// resolved entry and as another package's dependency is one node.
func TestPaketLockParses(t *testing.T) {
	a := New()
	dir := "testdata/paket"
	if !a.Detect(dir) {
		t.Fatal("should Detect a directory containing paket.lock")
	}
	if !a.Detect(filepath.Join(dir, "paket.lock")) {
		t.Fatal("should Detect a paket.lock file directly")
	}
	g, err := a.Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// root + FSharp.Core + Newtonsoft.Json + System.Net.Http + System.Runtime
	// + FAKE (from GROUP Build) = 6 nodes. System.Runtime appears as both a
	// resolved package and a dependency → one node. GITHUB source is skipped.
	nodes := g.SortedNodes()
	if len(nodes) != 6 {
		for _, n := range nodes {
			t.Logf("  node: %s (name=%s)", n.ID, n.Name)
		}
		t.Fatalf("nodes = %d, want 6", len(nodes))
	}
	// Canonical case for the case-sensitive OSV coordinate (D-62), lowercase PURL.
	nj := g.Get("pkg:nuget/newtonsoft.json@12.0.3")
	if nj == nil || nj.Name != "Newtonsoft.Json" {
		t.Errorf("Newtonsoft.Json node wrong: %+v", nj)
	}
	if snh := g.Get("pkg:nuget/system.net.http@4.3.0"); snh == nil || snh.Name != "System.Net.Http" {
		t.Errorf("System.Net.Http node wrong: %+v", snh)
	}
	// FAKE from GROUP Build must be present.
	if g.Get("pkg:nuget/fake@5.20.4") == nil {
		t.Error("FAKE (GROUP Build) missing — grouped NUGET sections must be read")
	}
	// A dependency edge from a package to System.Runtime must exist.
	sr := g.Get("pkg:nuget/system.runtime@4.3.1")
	if sr == nil {
		t.Fatal("System.Runtime node missing")
	}
	var edgeToSR bool
	for _, e := range g.SortedEdges() {
		if e.To == sr.ID && e.From == nj.ID {
			edgeToSR = true
		}
	}
	if !edgeToSR {
		t.Error("expected edge Newtonsoft.Json -> System.Runtime")
	}
}

// OPU-17: a paket.lock with no NUGET packages (only GITHUB/GIT sources, or
// empty) degrades honestly — an error the scan turns into incomplete coverage,
// not a crash or a silent clean pass.
func TestPaketLockNoNuGetIsError(t *testing.T) {
	only := "GITHUB\n  remote: fsharp/FAKE\n    src/x.fs (abc)\n"
	if _, err := parsePaketLock("proj", []byte(only)); err == nil {
		t.Error("a paket.lock with no NUGET packages must return an error")
	}
	if _, err := parsePaketLock("proj", []byte("")); err == nil {
		t.Error("an empty paket.lock must return an error")
	}
}

// packages.lock.json still wins over a paket.lock in the same directory — a
// resolved MSBuild lock is the standard, checked first.
func TestPaketLockPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "paket.lock"),
		[]byte("NUGET\n  remote: https://api.nuget.org/v3/index.json\n    OnlyInPaket (1.0.0)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := `{"version":1,"dependencies":{"net6.0":{"OnlyInMsbuild":{"type":"Direct","resolved":"2.0.0"}}}}`
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := New().Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Get("pkg:nuget/onlyinmsbuild@2.0.0") == nil {
		t.Error("packages.lock.json package missing — it should take precedence")
	}
	if g.Get("pkg:nuget/onlyinpaket@1.0.0") != nil {
		t.Error("paket.lock package present — packages.lock.json should have won")
	}
}

// Dedup still folds case: the same package listed in mixed case across TFMs is
// one node, not two.
func TestNuGetMixedCaseDedup(t *testing.T) {
	lock := []byte(`{"version":1,"dependencies":{
		"net6.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.3"}},
		"net8.0":{"newtonsoft.json":{"type":"Direct","resolved":"12.0.3"}}
	}}`)
	g, err := parsePackagesLock("proj", lock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	count := 0
	for _, n := range g.SortedNodes() {
		if n.ID == "pkg:nuget/newtonsoft.json@12.0.3" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("mixed-case package produced %d nodes, want 1 (dedup folds case)", count)
	}
}
