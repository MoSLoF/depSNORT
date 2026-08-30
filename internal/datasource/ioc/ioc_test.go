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

// TestTeamPCPExampleLedger keeps the shipped reference feed
// (docs/ioc-teampcp.example.json) honest: it must parse, and it must match the
// compromised releases by exact version while leaving a clean release alone. If
// the feed schema drifts, this fails rather than silently loading nothing.
func TestTeamPCPExampleLedger(t *testing.T) {
	f, err := Load(filepath.Join("..", "..", "..", "docs", "ioc-teampcp.example.json"))
	if err != nil {
		t.Fatalf("shipped TeamPCP ledger must load: %v", err)
	}
	if f.Len() != 3 {
		t.Fatalf("ledger Len=%d, want 3 (litellm 1.82.8, telnyx 4.87.1, telnyx 4.87.2)", f.Len())
	}

	// Every compromised release must match by exact version.
	compromised := []struct{ purl, eco, name, ver string }{
		{"pkg:pypi/litellm@1.82.8", "pypi", "litellm", "1.82.8"},
		{"pkg:pypi/telnyx@4.87.1", "pypi", "telnyx", "4.87.1"},
		{"pkg:pypi/telnyx@4.87.2", "pypi", "telnyx", "4.87.2"},
	}
	for _, c := range compromised {
		ind := f.Match(c.purl, c.eco, c.name, c.ver)
		if ind == nil {
			t.Errorf("%s must match the TeamPCP ledger", c.purl)
			continue
		}
		if ind.Severity != "critical" {
			t.Errorf("%s severity = %q, want critical", c.purl, ind.Severity)
		}
	}

	// A clean telnyx release must NOT match — a version-pinned indicator is
	// exact, so the ledger must never over-block a good version of a package
	// that also shipped a bad one.
	if ind := f.Match("pkg:pypi/telnyx@4.85.0", "pypi", "telnyx", "4.85.0"); ind != nil {
		t.Errorf("a clean telnyx release must not match the ledger; got %+v", ind)
	}
}
