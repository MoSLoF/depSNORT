package nuget

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/graph"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// pkgSet returns name@version for every non-root package node.
func pkgSet(t *testing.T, g *graph.Graph) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, n := range g.SortedNodes() {
		if n.Ecosystem == "nuget" && n.Depth > 0 {
			out[n.Name+"@"+n.Version] = true
		}
	}
	return out
}

func rootOf(g *graph.Graph) *graph.Node {
	for _, r := range g.Roots {
		return g.Get(r)
	}
	return nil
}

// The modern .NET surface: every format below resolved to ZERO packages before
// this reader existed (StreamDivert live-fire), so a PackageReference project —
// the SDK-style default since VS2017 — was entirely invisible.
func TestMSBuildFormatsResolve(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"PackageReference (csproj)", map[string]string{
			"App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
				<PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
		}, "Newtonsoft.Json@12.0.1"},

		{"PackageReference (vcxproj, Version as child element)", map[string]string{
			"App.vcxproj": `<Project><ItemGroup>
				<PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference></ItemGroup></Project>`,
		}, "Serilog@2.10.0"},

		{"Central Package Management", map[string]string{
			"App.csproj":               `<Project><ItemGroup><PackageReference Include="Serilog" /></ItemGroup></Project>`,
			"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Serilog" Version="2.10.0" /></ItemGroup></Project>`,
		}, "Serilog@2.10.0"},

		{"GlobalPackageReference", map[string]string{
			"Directory.Packages.props": `<Project><ItemGroup>
				<GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.6.133" /></ItemGroup></Project>`,
		}, "Nerdbank.GitVersioning@3.6.133"},

		{"Directory.Build.props", map[string]string{
			"Directory.Build.props": `<Project><ItemGroup>
				<PackageReference Include="StyleCop.Analyzers" Version="1.1.118" /></ItemGroup></Project>`,
		}, "StyleCop.Analyzers@1.1.118"},

		{"MSBuild property expansion", map[string]string{
			"Directory.Build.props": `<Project><PropertyGroup><SerilogVer>2.12.0</SerilogVer></PropertyGroup></Project>`,
			"App.csproj":            `<Project><ItemGroup><PackageReference Include="Serilog" Version="$(SerilogVer)" /></ItemGroup></Project>`,
		}, "Serilog@2.12.0"},

		{"exact bracketed pin", map[string]string{
			"App.csproj": `<Project><ItemGroup><PackageReference Include="Serilog" Version="[2.10.0]" /></ItemGroup></Project>`,
		}, "Serilog@2.10.0"},

		{"nuspec dependency", map[string]string{
			"My.nuspec": `<package><metadata><id>My</id><dependencies>
				<dependency id="Newtonsoft.Json" version="12.0.1" /></dependencies></metadata></package>`,
		}, "Newtonsoft.Json@12.0.1"},

		{"nuspec grouped dependency", map[string]string{
			"My.nuspec": `<package><metadata><id>My</id><dependencies><group targetFramework="net6.0">
				<dependency id="Serilog" version="2.10.0" /></group></dependencies></metadata></package>`,
		}, "Serilog@2.10.0"},

		{"dotnet-tools.json (tools execute)", map[string]string{
			filepath.Join(".config", "dotnet-tools.json"): `{"version":1,"tools":{"dotnet-ef":{"version":"7.0.0"}}}`,
		}, "dotnet-ef@7.0.0"},

		{"project.json (legacy .NET Core)", map[string]string{
			"project.json": `{"dependencies":{"Newtonsoft.Json":"12.0.1"}}`,
		}, "Newtonsoft.Json@12.0.1"},

		{"project.json object form", map[string]string{
			"project.json": `{"dependencies":{"Serilog":{"version":"2.10.0","type":"build"}}}`,
		}, "Serilog@2.10.0"},

		{"paket.dependencies (no lock)", map[string]string{
			"paket.dependencies": "source https://api.nuget.org/v3/index.json\nnuget Newtonsoft.Json 12.0.1\n",
		}, "Newtonsoft.Json@12.0.1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeFiles(t, c.files)
			if !(&Adapter{}).Detect(dir) {
				t.Fatalf("Detect must claim a directory with %s", c.name)
			}
			g, err := (&Adapter{}).Resolve(dir)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := pkgSet(t, g); !got[c.want] {
				t.Errorf("want %s resolved, got %v", c.want, got)
			}
		})
	}
}

// project.assets.json is the only modern format with a REAL transitive tree, so
// it must produce package->package edges, not a flat list.
func TestProjectAssetsGivesTransitiveEdges(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		filepath.Join("obj", "project.assets.json"): `{"version":3,"targets":{"net6.0":{
			"Serilog/2.10.0":{"type":"package","dependencies":{"Newtonsoft.Json":"12.0.1"}},
			"Newtonsoft.Json/12.0.1":{"type":"package"},
			"MyLocalProj/1.0.0":{"type":"project"}}}}`,
	})
	g, err := (&Adapter{}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := pkgSet(t, g)
	if !got["Serilog@2.10.0"] || !got["Newtonsoft.Json@12.0.1"] {
		t.Fatalf("both packages must resolve, got %v", got)
	}
	if got["MyLocalProj@1.0.0"] {
		t.Error(`"project" entries are local project references, not NuGet packages`)
	}
	// The transitive edge Serilog -> Newtonsoft.Json must exist.
	var found bool
	for _, e := range g.SortedEdges() {
		// PURL coordinates are case-normalized, so compare case-insensitively.
		from, to := strings.ToLower(e.From), strings.ToLower(e.To)
		if strings.Contains(from, "serilog") && strings.Contains(to, "newtonsoft.json") {
			found = true
		}
	}
	if !found {
		t.Error("project.assets.json must yield the transitive Serilog -> Newtonsoft.Json edge")
	}
	// Not flat: it records a resolved tree.
	if r := rootOf(g); r != nil && r.Attr[graph.AttrFlatResolution] != "" {
		t.Error("project.assets.json is a resolved tree and must not be marked flat")
	}
}

// BLIND-SPOT GUARD: a version that cannot be pinned statically must be DISCLOSED
// as unresolved, never guessed and never silently dropped (D-59).
func TestUnpinnableVersionsAreDisclosed(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"App.csproj": `<Project><ItemGroup>
			<PackageReference Include="Pinned" Version="1.0.0" />
			<PackageReference Include="Floating" Version="1.2.*" />
			<PackageReference Include="RangeDep" Version="[1.0,2.0)" />
			<PackageReference Include="NoVersion" />
			<PackageReference Include="FromMissingProp" Version="$(NeverDefined)" />
		</ItemGroup></Project>`,
	})
	g, err := (&Adapter{}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := pkgSet(t, g)
	if !got["Pinned@1.0.0"] {
		t.Error("the pinned package must still resolve")
	}
	root := rootOf(g)
	if root == nil {
		t.Fatal("no root")
	}
	unresolved := root.Attr[graph.AttrUnresolved]
	for _, name := range []string{"Floating", "RangeDep", "NoVersion", "FromMissingProp"} {
		if !strings.Contains(unresolved, name) {
			t.Errorf("%s must be disclosed as unresolved, got %q", name, unresolved)
		}
		// and must never be invented at some made-up version
		for k := range got {
			if strings.HasPrefix(k, name+"@") {
				t.Errorf("%s must NOT be given a fabricated version (%s)", name, k)
			}
		}
	}
	if root.Attr[graph.AttrUnresolvedCount] != "4" {
		t.Errorf("unresolved_count = %q, want 4", root.Attr[graph.AttrUnresolvedCount])
	}
	// Declared-only formats must be marked flat (D-24).
	if root.Attr[graph.AttrFlatResolution] != "nuget" {
		t.Error("declared PackageReference resolution must be disclosed as flat")
	}
}

// Lockfile precedence must be preserved: a resolved lockfile always wins over
// declared manifests in the same directory.
func TestLockfilePrecedencePreserved(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"App.csproj": `<Project><ItemGroup><PackageReference Include="Declared" Version="9.9.9" /></ItemGroup></Project>`,
		"packages.lock.json": `{"version":1,"dependencies":{"net6.0":{
			"Locked":{"type":"Direct","resolved":"1.0.0"}}}}`,
	})
	g, err := (&Adapter{}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := pkgSet(t, g); !got["Locked@1.0.0"] {
		t.Errorf("packages.lock.json must win, got %v", got)
	}
}

// A project mid-migration (packages.config alongside PackageReference) must be
// covered by BOTH, or half its dependencies become a blind spot.
func TestPackagesConfigAndPackageReferenceMerge(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"packages.config": `<?xml version="1.0"?><packages>
			<package id="LegacyPkg" version="1.0.0" /></packages>`,
		"App.csproj": `<Project><ItemGroup>
			<PackageReference Include="ModernPkg" Version="2.0.0" /></ItemGroup></Project>`,
	})
	g, err := (&Adapter{}).Resolve(dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := pkgSet(t, g)
	if !got["LegacyPkg@1.0.0"] || !got["ModernPkg@2.0.0"] {
		t.Errorf("both legacy and modern declarations must resolve, got %v", got)
	}
}
