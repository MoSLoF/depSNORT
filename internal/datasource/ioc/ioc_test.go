package ioc

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFeed(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAndMatchSpecificity(t *testing.T) {
	p := writeFeed(t, `{
	  "version": 1,
	  "indicators": [
	    {"ecosystem":"npm","name":"evil","version":"2.0.0","severity":"critical"},
	    {"ecosystem":"npm","name":"anyver","severity":"high"},
	    {"purl":"pkg:pypi/bad@1.0.0","severity":"high"}
	  ]
	}`)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.Len() != 3 {
		t.Fatalf("Len=%d want 3", f.Len())
	}

	// exact version
	if f.Match("pkg:npm/evil@2.0.0", "npm", "evil", "2.0.0") == nil {
		t.Error("exact ecosystem+name+version must match")
	}
	// wrong version must NOT match a version-pinned indicator
	if f.Match("pkg:npm/evil@1.0.0", "npm", "evil", "1.0.0") != nil {
		t.Error("a version-pinned indicator must not match a different version")
	}
	// any-version indicator
	if f.Match("pkg:npm/anyver@9.9.9", "npm", "anyver", "9.9.9") == nil {
		t.Error("a version-less indicator must match any version")
	}
	// PURL indicator
	if f.Match("pkg:pypi/bad@1.0.0", "pypi", "bad", "1.0.0") == nil {
		t.Error("a PURL indicator must match by node ID")
	}
	// unrelated package
	if f.Match("pkg:npm/fine@1.0.0", "npm", "fine", "1.0.0") != nil {
		t.Error("an unrelated package must not match")
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	p := writeFeed(t, `{"version": 2, "indicators": []}`)
	if _, err := Load(p); err == nil {
		t.Error("an unsupported feed version must be rejected")
	}
}
