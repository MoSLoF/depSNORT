package installsurface

import "testing"

// Assessment follow-up to D-154: the --dry-run carve-out for a CLI publish used
// to be judged across the WHOLE hook, so a single `--dry-run` anywhere masked a
// real publish elsewhere in the same script — a worm-step false negative on the
// critical/block VC-002k signal. The carve-out is now per command segment.

// TestDryRunFollowedByRealPublishStillPropagates is the false negative the fix
// closes: a rehearsal and then a genuine publish must count.
func TestDryRunFollowedByRealPublishStillPropagates(t *testing.T) {
	for name, src := range map[string]string{
		"npm rehearsal then real":   "npm publish --dry-run && npm publish",
		"cargo rehearsal then real": "cp.execSync('cargo publish --dry-run'); cp.execSync('cargo publish --token $T')",
		"decoy dry-run beside real": "cargo publish --dry-run | tee log; gem push wormy-1.0.0.gem",
		"real then rehearsal":       "npm publish; npm publish --dry-run",
	} {
		if !hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("%s: a real publish beside a --dry-run must still be propagation: %q -> %v",
				name, src, d152Caps(t, src))
		}
	}
}

// TestLoneDryRunIsStillNotPropagation is the boundary the fix must not regress:
// a rehearsal with no accompanying real publish is not the worm step.
func TestLoneDryRunIsStillNotPropagation(t *testing.T) {
	for name, src := range map[string]string{
		"npm dry-run only":         "npm publish --dry-run",
		"cargo dry-run only":       "cp.execSync('cargo publish --dry-run')",
		"cargo dry-run with token": "cp.execSync('cargo publish --token $T --dry-run')",
		"two rehearsals, no real":  "npm publish --dry-run && cargo publish --dry-run",
	} {
		if hasCap(d152Caps(t, src), CapPropagate) {
			t.Errorf("%s: a lone --dry-run rehearsal is not propagation: %q -> %v",
				name, src, d152Caps(t, src))
		}
	}
}
