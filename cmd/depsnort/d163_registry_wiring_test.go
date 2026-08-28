package main

import "testing"

// D-163 registration pin: every ecosystem adapters emit nodes for must have
// its release-history source wired, or its temporal checks (VC-004 and
// friends) silently never evaluate — the maven shape: D-162 gave maven nodes
// advisory coverage while registry metadata stayed dark until this source
// landed. A source disappearing from this list is exactly the kind of quiet
// coverage regression a test must catch, since a scan without it still exits
// green.
func TestRegistrySourcesCoverEmittedEcosystems(t *testing.T) {
	have := map[string]bool{}
	for _, s := range registrySources(t.TempDir(), true) {
		have[s.Ecosystem()] = true
	}
	for _, eco := range []string{"npm", "pypi", "gem", "cargo", "composer", "nuget", "gomod", "maven"} {
		if !have[eco] {
			t.Errorf("no registry release-history source wired for ecosystem %q", eco)
		}
	}
}
