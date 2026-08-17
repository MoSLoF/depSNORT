package npmreg

import "testing"

// TestParsePackumentCapturesPerVersionPublisherAndHooks: both facts come from
// the packument this scan already fetches and caches, so the actor axis and
// hook-level drift cost no additional request (D-40).
func TestParsePackumentCapturesPerVersionPublisherAndHooks(t *testing.T) {
	raw := []byte(`{
	  "name": "acme-widget",
	  "time": {
	    "created": "2026-01-01T00:00:00.000Z",
	    "1.0.0": "2026-01-01T00:00:00.000Z",
	    "1.0.1": "2026-02-01T00:00:00.000Z",
	    "1.0.2": "2026-03-01T00:00:00.000Z"
	  },
	  "maintainers": [{"name": "alice", "email": "alice@example.invalid"}],
	  "versions": {
	    "1.0.0": {"_npmUser": {"name": "alice", "email": "alice@example.invalid"},
	              "scripts": {"test": "node test"}},
	    "1.0.1": {"_npmUser": {"name": "alice", "email": "alice@example.invalid"},
	              "scripts": {"build": "tsc"}},
	    "1.0.2": {"_npmUser": {"name": "mallory", "email": "m@example.invalid"},
	              "scripts": {"postinstall": "node ./setup.js", "test": "node test"}}
	  }
	}`)

	h, err := parsePackument("acme-widget", raw)
	if err != nil {
		t.Fatalf("parsePackument: %v", err)
	}

	p, ok := h.PublisherAt("1.0.2")
	if !ok || p.Key() != "mallory" {
		t.Fatalf("PublisherAt(1.0.2) = (%+v, %v), want mallory", p, ok)
	}
	if p.Source != "npm._npmUser" {
		t.Errorf("Source = %q, want npm._npmUser", p.Source)
	}

	keys, known := h.PriorPublishers("1.0.2")
	if !known || len(keys) != 1 || !keys["alice"] {
		t.Errorf("prior publishers = %v (known=%v), want {alice}", keys, known)
	}

	// Hooks: only install-time names count. A `test` or `build` script is not
	// something npm install fires, and counting them would make the drift
	// signal fire on nearly every release of nearly every package.
	if got := h.Hooks["1.0.2"]; len(got) != 1 || got[0] != "postinstall" {
		t.Errorf("Hooks[1.0.2] = %v, want [postinstall]", got)
	}
	if got, ok := h.Hooks["1.0.1"]; ok {
		t.Errorf("Hooks[1.0.1] = %v, want no entry: a build script is not an install hook", got)
	}

	// The package-level maintainer list still reads identically across the
	// takeover — which is exactly why per-version publishers had to exist.
	if len(h.Maintainers) != 1 || h.Maintainers[0] != "alice" {
		t.Errorf("Maintainers = %v, want [alice]", h.Maintainers)
	}
}

func TestParsePackumentWithoutVersionsBlock(t *testing.T) {
	raw := []byte(`{"name": "acme-widget", "time": {"1.0.0": "2026-01-01T00:00:00.000Z"}}`)
	h, err := parsePackument("acme-widget", raw)
	if err != nil {
		t.Fatalf("parsePackument: %v", err)
	}
	if len(h.Releases) != 1 {
		t.Errorf("releases = %d, want 1", len(h.Releases))
	}
	if len(h.Publishers) != 0 || len(h.Hooks) != 0 {
		t.Error("a packument with no versions block must record no publishers and no hooks")
	}
}

func TestInstallHooksOfIgnoresEmptyBodies(t *testing.T) {
	got := installHooksOf(map[string]string{
		"postinstall": "  ",
		"preinstall":  "node ./a.js",
		"prepare":     "node ./b.js",
		"test":        "node test",
	})
	if len(got) != 2 || got[0] != "preinstall" || got[1] != "prepare" {
		t.Errorf("installHooksOf = %v, want [preinstall prepare] sorted", got)
	}
}
