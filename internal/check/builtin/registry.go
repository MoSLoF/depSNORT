package builtin

import "ihbv.io/depsnort/internal/check"

// Default returns the canonical v0 check pack, in check-ID order.
//
// This is the SINGLE registration point for the builtin checks (Decision D-37).
// The CLI and the adversarial corpus both build their registry from here, so a
// check cannot be live in production while the regression corpus stays blind to
// it.
//
// That drift is not hypothetical: the adversarial harness used to hand-roll a
// five-check registry that omitted VC-002f. Because VC-002b deliberately defers
// to VC-002f whenever the cradle capability is set, the composer-plugin cradle
// attack scored ZERO findings in the corpus — the suite reported a miss on an
// attack the shipping binary blocks correctly. A hand-maintained second
// registry is the bug; this function removes the second registry.
func Default() *check.Registry {
	return check.NewRegistry(
		MaliciousVersion{},    // VC-001
		HookPresent{},         // VC-002a
		HookNetwork{},         // VC-002b
		HookCredentials{},     // VC-002c
		HookExfilCapable{},    // VC-002d
		HookObfuscated{},      // VC-002e
		HookDownloadCradle{},  // VC-002f
		IOCMatch{},            // VC-003
		Dormancy{},            // VC-004
		PatchBurst{},          // VC-005
		Typosquat{},           // VC-006
		DependencyConfusion{}, // VC-007
		KnownVuln{},           // VC-008
		UnverifiableSource{},  // VC-009
		CapabilityDrift{},     // VC-010
		PublisherLineage{},    // VC-011
	)
}
